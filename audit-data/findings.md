for details, see https://immunefisupport.zendesk.com/hc/en-us/articles/12435277406481-Bug-Report-Template

### [H-1] Storing the password on-chain makes it visible to anyone, and no longer private

**Description:** All data stored on-chain is visible to anyone, and can be read directly from the blockchain. The `PasswordStore::s_password` variable is intended to be a private and only accessed through the `PasswordStore::getPassword` function, which is intended to be only called by the owner of the contract.

we show one such method of reading any data off chain below

**Impact:** anyone can read the private password, severly breaking the functionality of the protocol

**Proof of Concept:** (or proof of code)
the below test case shows how anyone can read the password directly from the blockchain.

1. run `anvil` to start a little fake blockchain running

2. deploy the PasswordStore to this locally running blockchain
   `make deploy` doesn't work so
   `forge script script/DeployPasswordStore.s.sol:DeployPasswordStore --rpc-url http://localhost:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast`
3. then run the storage tool :
   `cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 1 --rpc-url http://127.0.0.1:8545`
   `1` because this is the second variable

4. i get '0x6d7950617373776f726400000000000000000000000000000000000000000014' & you can parse that hex to a string with
   `cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014` and you get an output of :

`myPassword`
YEAHHHHHHHHHHHHHHH

**Recommended Mitigation:**
Due to this, the overall architecture of the contract should be rethought. One could encrypt the password off-chain, and then store the encrypted password on-chain. This would require the user to remember another password off-chain to decrypt the password. However, you'd also likely want to remove the view function as you wouldn't want the user to accidentally send a transaction with the password that decrypts your password.

```

```

### [H-2] `PasswordStore::setPassword` has no access controls, meaning a non-owner could change the password

**Description:** The `PasswordStore::setPassword` function is set to be an `external` function, however, the natspec of the function and overall purpose of the smart contract is that `This function allows only the owner to set a new password.`

```javascript
     function setPassword(string memory newPassword) external {
        s_password = newPassword;
        emit SetNetPassword();
    }

```

**Impact:** anyone can set/change the password of the contract, severly breaking the contract intended functionality

**Proof of Concept:** add the following to the `PasswordStore.t.sol` test file

<details>
<summary>code</summary>

```javascript
      function test_anyone_can_set_password(address randomAddress) public {
        vm.assume(randomAddress != owner); // make sure the random address is not the owner
        vm.prank(randomAddress); // Let's pretend that randomAddress is making the next transaction
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword); // call the setPassword function of passwordStore, passing in the expectedPassword ("myNewPassword") as the new password.

        vm.prank(owner); // Let's pretend that the owner is making the next transaction
        string memory actualPassword = passwordStore.getPassword(); // the owner calls the getPassword function of the passwordStore contract, which retrieves the currently stored password
        assertEq(actualPassword, expectedPassword); // check that the actualPassword is equal to the expectedPassword
    }
```

</details>

run `forge test --mt test_anyone_can_set_password`

**Recommended Mitigation:** Add an access control conditional to the `setPaswword` function.

```javascript
    if(msg.sender != s_owner){
      revert PasswordStore_NotOwner();
    }

```

### [I-1] The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exist, causing the natspect to be incorrect

**Description:**

```javascript
     /*
     * @notice This allows only the owner to retrieve the password.
     * @param newPassword The new password to set.
     */
     function getPassword() external view returns (string memory) {}

```

The `PasswordStore::getPassword` function signature is `getPassword()` which the napstec say it should be `getPassword(string)`

**Impact:** the napstec is incorrect

**Proof of Concept:**

**Recommended Mitigation:** Remove the incorrect natspect line

```diff
-     * @param newPassword The new password to set.
```

## [H-1] Likelihood & Impact:

-Impact ? HIGH
Are the funds directly at risk ? no
Severe disruption of protocol functionality ? YES
-Likelihood : HIGH
-so severity : HIGH

## [H-2] Likelihood & Impact

-Impact : HIGH
-Likelihood : HIGH
-Severity : HIGH

## [I-1]Likelihood & Impact

-Impact : none
-Likelihood : H
-Severity : iNFORMATIONAL/GAS/NON-CRITS
