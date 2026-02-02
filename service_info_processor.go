// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

// ServiceInfoProcessor - unified FSIM processing for both 1.0.1 and 2.0
// This contains the EXACT working logic from 1.0.1 ownerServiceInfo method
// NO CHANGES to the logic - just extracted to a common location

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// ServiceInfoProcessor holds the dependencies needed for FSIM processing
type ServiceInfoProcessor struct {
	Modules   serviceinfo.ModuleStateMachine
	Session   TO2SessionState
	Vouchers  OwnerVoucherPersistentState
	OwnerKeys OwnerKeyPersistentState
}

// ServiceInfoResponse is the unified response type for both 1.0.1 and 2.0
type ServiceInfoResponse struct {
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []*serviceinfo.KV
}

// ProcessServiceInfo - THE CORE API that both versions use
// This is the EXACT working logic from 1.0.1 ownerServiceInfo method
func (p *ServiceInfoProcessor) ProcessServiceInfo(ctx context.Context, deviceInfo *deviceServiceInfo) (*ServiceInfoResponse, error) {
	// Get next owner service info module (EXACT same as 1.0.1)
	var moduleName string
	var module serviceinfo.OwnerModule
	if devmod, modules, complete, err := p.Session.Devmod(ctx); errors.Is(err, ErrNotFound) || (err == nil && !complete) {
		moduleName, module = "devmod", &devmodOwnerModule{
			Devmod:  devmod,
			Modules: modules,
		}
	} else if err != nil {
		return nil, fmt.Errorf("error getting devmod state: %w", err)
	} else {
		var err error
		moduleName, module, err = p.Modules.Module(ctx)
		if err != nil {
			return nil, fmt.Errorf("error getting current service info module: %w", err)
		}

		// Set the context values that an FSIM expects (EXACT same as 1.0.1)
		guid, err := p.Session.GUID(ctx)
		if err != nil {
			return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
		}
		ov, err := p.Vouchers.Voucher(ctx, guid)
		if err != nil {
			return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
		}
		var deviceCertChain []*x509.Certificate
		if ov.CertChain != nil {
			deviceCertChain = make([]*x509.Certificate, len(*ov.CertChain))
			for i, cert := range *ov.CertChain {
				deviceCertChain[i] = (*x509.Certificate)(cert)
			}
		}
		ctx = serviceinfo.Context(ctx, &devmod, deviceCertChain)
	}

	// Handle data with owner module (EXACT same as 1.0.1)
	unchunked, unchunker := serviceinfo.NewChunkInPipe(len(deviceInfo.ServiceInfo))
	for _, kv := range deviceInfo.ServiceInfo {
		if err := unchunker.WriteChunk(kv); err != nil {
			return nil, fmt.Errorf("error unchunking received device service info: write: %w", err)
		}
	}
	if err := unchunker.Close(); err != nil {
		return nil, fmt.Errorf("error unchunking received device service info: close: %w", err)
	}
	for {
		key, messageBody, ok := unchunked.NextServiceInfo()
		if !ok {
			break
		}
		moduleName, messageName, _ := strings.Cut(key, ":")
		if err := module.HandleInfo(ctx, messageName, messageBody); err != nil {
			return nil, fmt.Errorf("error handling device service info %q: %w", key, err)
		}
		if n, err := io.Copy(io.Discard, messageBody); err != nil {
			return nil, err
		} else if n > 0 {
			return nil, fmt.Errorf(
				"owner module did not read full body of message '%s:%s'",
				moduleName, messageName)
		}
		if err := messageBody.Close(); err != nil {
			return nil, fmt.Errorf("error closing unchunked message body for %q: %w", key, err)
		}
	}

	// Save devmod state (original 1.0.1 logic - no early transition)
	if devmod, ok := module.(*devmodOwnerModule); ok {
		if err := p.Session.SetDevmod(ctx, devmod.Devmod, devmod.Modules, false); err != nil {
			return nil, fmt.Errorf("error storing devmod state: %w", err)
		}
	}

	// Allow owner module to produce data unless blocked by device (EXACT same as 1.0.1)
	if !deviceInfo.IsMoreServiceInfo {
		return p.produceServiceInfo(ctx, moduleName, module)
	}

	// Store the current module state (EXACT same as 1.0.1)
	if modules, ok := p.Modules.(serviceinfo.ModulePersister); ok {
		if err := modules.PersistModule(ctx, moduleName, module); err != nil {
			return nil, fmt.Errorf("error persisting service info module %q state: %w", moduleName, err)
		}
	}

	return &ServiceInfoResponse{
		IsMoreServiceInfo: false,
		IsDone:            false,
		ServiceInfo:       nil,
	}, nil
}

// produceServiceInfo - THE CORE API for producing service info
// This is the EXACT working logic from 1.0.1 produceOwnerServiceInfo method
func (p *ServiceInfoProcessor) produceServiceInfo(ctx context.Context, moduleName string, module serviceinfo.OwnerModule) (*ServiceInfoResponse, error) {
	mtu, err := p.Session.MTU(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting max device service info size: %w", err)
	}

	// Get service info produced by the module (EXACT same as 1.0.1)
	producer := serviceinfo.NewProducer(moduleName, mtu)
	explicitBlock, complete, err := module.ProduceInfo(ctx, producer)
	if err != nil {
		return nil, fmt.Errorf("error producing owner service info from module: %w", err)
	}
	if explicitBlock && complete {
		slog.Warn("service info module completed but indicated that it had more service info to send", "module", moduleName)
		explicitBlock = false
	}
	serviceInfo := producer.ServiceInfo()
	if size := serviceinfo.ArraySizeCBOR(serviceInfo); size > int64(mtu) {
		return nil, fmt.Errorf("owner service info module produced service info exceeding the MTU=%d - 3 (message overhead), size=%d", mtu, size)
	}

	// Store the current module state (EXACT same as 1.0.1)
	if devmod, ok := module.(*devmodOwnerModule); ok {
		if err := p.Session.SetDevmod(ctx, devmod.Devmod, devmod.Modules, complete); err != nil {
			return nil, fmt.Errorf("error storing devmod state: %w", err)
		}
	}
	if modules, ok := p.Modules.(serviceinfo.ModulePersister); ok {
		if err := modules.PersistModule(ctx, moduleName, module); err != nil {
			return nil, fmt.Errorf("error persisting service info module %q state: %w", moduleName, err)
		}
	}

	// Progress the module state machine when the module completes (EXACT same as 1.0.1)
	allModulesDone := false
	if complete {
		// Cleanup current module
		if plugin, ok := module.(plugin.Module); ok {
			stopOwnerPlugin(ctx, moduleName, plugin)
		}

		// Find out if there will be more modules
		moreModules, err := p.Modules.NextModule(ctx)
		if err != nil {
			return nil, fmt.Errorf("error progressing service info module %q state: %w", moduleName, err)
		}
		allModulesDone = !moreModules
	}

	// Return chunked data (EXACT same as 1.0.1)
	return &ServiceInfoResponse{
		IsMoreServiceInfo: explicitBlock,
		IsDone:            allModulesDone,
		ServiceInfo:       serviceInfo,
	}, nil
}
