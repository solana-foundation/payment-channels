import { constantPdaSeedNodeFromString, pdaValueNode, programIdValueNode } from '@codama/nodes';
import { addPdasVisitor, setInstructionAccountDefaultValuesVisitor } from '@codama/visitors';

/// Derives the event authority PDA so generated clients can autofill it.
export const addEventAuthorityPda = addPdasVisitor({
  paymentChannels: [
    {
      name: 'eventAuthority',
      seeds: [constantPdaSeedNodeFromString('utf8', 'event_authority')],
    },
  ],
});

/// Default `eventAuthority` and `selfProgram` accounts on any ix that lists them.
export const setEventAuthorityAndSelfProgramDefaults = setInstructionAccountDefaultValuesVisitor([
  { account: 'eventAuthority', defaultValue: pdaValueNode('eventAuthority') },
  { account: 'selfProgram', defaultValue: programIdValueNode() },
]);
