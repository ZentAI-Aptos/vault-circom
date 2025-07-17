pragma circom 2.0.0;

// Import necessary components from the circomlib library
include "node_modules/circomlib/circuits/pedersen.circom";
include "node_modules/circomlib/circuits/mimcsponge.circom";

// Main template for verifying a Withdraw transaction
// 'levels' is the depth of the Merkle tree
template Withdraw(levels) {
    // --- Private Inputs ---
    // These are the secrets known only to the user, provided to the prover.
    // They are not revealed on-chain.

    // Secrets of the input commitment (the note being spent)
    signal private input valueIn;
    signal private input blindingIn;

    // Secrets of the change commitment (the new note being created)
    signal private input valueChange;
    signal private input blindingChange;
    
    // Secret to generate the nullifier, ensuring each note is spent only once
    signal private input nullifierSecret;

    // Data for the Merkle proof
    signal private input pathElements[levels]; // The sibling nodes along the path to the root
    signal private input pathIndices[levels]; // The 0/1 bits indicating left/right position at each level


    // --- Public Inputs ---
    // These are the public data that the smart contract will receive and verify against

    signal public input merkleRoot; // The root of the Merkle tree at the time of proof generation
    signal public input nullifierHash; // The hash of the nullifier to prevent double-spending
    
    signal public input publicAmount; // The amount being publicly withdrawn

    signal public input commitmentIn[2]; // The commitment of the input note
    signal public input commitmentChange[2]; // The commitment of the change note


    // --- Logic and Constraints ---

    // 1. Verify that the input commitment was correctly formed from its secrets
    component pedersenIn = Pedersen(2);
    pedersenIn.inputs[0] <== valueIn;
    pedersenIn.inputs[1] <== blindingIn;
    commitmentIn[0] === pedersenIn.out[0];
    commitmentIn[1] === pedersenIn.out[1];

    // 2. Verify that the change commitment was correctly formed from its secrets
    component pedersenChange = Pedersen(2);
    pedersenChange.inputs[0] <== valueChange;
    pedersenChange.inputs[1] <== blindingChange;
    commitmentChange[0] === pedersenChange.out[0];
    commitmentChange[1] === pedersenChange.out[1];

    // 3. Verify value conservation: valueIn = publicAmount + valueChange
    valueIn === publicAmount + valueChange;

    // 4. Verify the Nullifier Hash
    component nullifierHasher = MiMCSponge(1, 220, 1);
    nullifierHasher.ins[0] <== nullifierSecret;
    nullifierHasher.k <== 0;
    nullifierHash === nullifierHasher.outs[0];

    // 5. Verify the Merkle Path
    // Recalculate the Merkle root from the leaf and path, then compare it to the public root
    component merklePathCheckers[levels];
    component leafHasher = Pedersen(2);
    leafHasher.inputs[0] <== commitmentIn[0];
    leafHasher.inputs[1] <== commitmentIn[1];
    
    signal currentHash <== leafHasher.out[0]; // Only take the x-coordinate of the point as the hash

    for (var i = 0; i < levels; i++) {
        merklePathCheckers[i] = MiMCSponge(2, 220, 1);
        // pathIndices[i] determines the hashing order (left first or right first)
        merklePathCheckers[i].ins[0] <== pathIndices[i] * (pathElements[i] - currentHash) + currentHash;
        merklePathCheckers[i].ins[1] <== pathIndices[i] * (currentHash - pathElements[i]) + pathElements[i];
        merklePathCheckers[i].k <== 0;
        currentHash <== merklePathCheckers[i].outs[0];
    }
    
    merkleRoot === currentHash;
}

// Instantiate a main component with a Merkle tree depth of 32
component main {public [merkleRoot, nullifierHash, publicAmount, commitmentIn, commitmentChange]} = Withdraw(32);