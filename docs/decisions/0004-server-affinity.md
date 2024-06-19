# 4. Server Affinity

Date: 2024-06-18

## Status

Accepted

## Context

Device onboarding should be measured in devices per day, not per second. Nonetheless, horizontal scaling of some components may be desirable.

A rendezvous (TO1) server will generally see more traffic than an owner service and thus may need more than just vertical scaling. In the case of owner services, particularly memory usage-heavy FSIMs could necessitate horizontal scaling as well.

## Considered Options

Where a "protocol session" is defined as a sequence of messages of a single protocol (DI, TO0, TO1, TO2) sent to and from one client until the sequence ends in either success or error:

- All messages for a given protocol session must be sent to exactly one server
  - Easiest to implement, but cannot scale horizontally
- All messages may be sent to any server
  - Hardest to implement, can scale horizontally
  - May incur performance penalty in service info subprotocol
- All messages may be sent to any server, but within a protocol session repeated message numbers must be sent to the same server
  - Less difficult to implement due mainly to the state that must be stored in the 68->69 loop, can scale horizontally if selecting server by message number (for TO2)
  - Smaller performance penalty, but significant for FSIMs that exchange many messages

## Decision

The 68->69 loop will maintain state that does not propagate between servers when the implementation of the server state interfaces are horizontally scaled.

## Consequences

This significantly simplifies implementation and the scaling limitation can be worked around by using the message number in the path as a key for server selection.

This decision can be overridden - potentially optionally - in the future if a plan for maintaining code maintainability is made.
