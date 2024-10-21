// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import {Test, console} from "forge-std/Test.sol";
import {PasswordStore} from "../src/PasswordStore.sol";
import {DeployPasswordStore} from "../script/DeployPasswordStore.s.sol";

contract PasswordStoreTest is Test {
    PasswordStore public passwordStore;
    DeployPasswordStore public deployer;
    address public owner;

    function setUp() public {
        deployer = new DeployPasswordStore();
        passwordStore = deployer.run();
        owner = msg.sender;
    }

    function test_owner_can_set_password() public {
        vm.startPrank(owner);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);
        string memory actualPassword = passwordStore.getPassword();
        assertEq(actualPassword, expectedPassword);
    }

    function test_non_owner_reading_password_reverts() public {
        vm.startPrank(address(1));

        vm.expectRevert(PasswordStore.PasswordStore__NotOwner.selector);
        passwordStore.getPassword();
    }


 // write a new test to prove anyone can set the password
    function test_anyone_can_set_password(address randomAddress) public {
        vm.assume(randomAddress != owner); // make sure the random address is not the owner
        vm.prank(randomAddress); // Let's pretend that randomAddress is making the next transaction
        string memory expectedPassword = "myNewPassword"; 
        passwordStore.setPassword(expectedPassword); // call the setPassword function of passwordStore, passing in the expectedPassword ("myNewPassword") as the new password.

        vm.prank(owner); // Let's pretend that the owner is making the next transaction
        string memory actualPassword = passwordStore.getPassword(); // the owner calls the getPassword function of the passwordStore contract, which retrieves the currently stored password
        assertEq(actualPassword, expectedPassword); // check that the actualPassword is equal to the expectedPassword
    }


}
