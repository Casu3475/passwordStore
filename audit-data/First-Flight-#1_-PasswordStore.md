# First Flight #1: PasswordStore - Findings Report

# Table of contents
- ### [Contest Summary](#contest-summary)
- ### [Results Summary](#results-summary)
- ## High Risk Findings
    - [H-01. Anyone can set the password by calling `PasswordStore::setPassword`](#H-01)
    - [H-02. Owner's password stored in the `s_password` state variable is not a secret and can be seen by everyone](#H-02)

- ## Low Risk Findings
    - [L-01. Initialization Timeframe Vulnerability](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #1

### Dates: Oct 18th, 2023 - Oct 25th, 2023

[See more contest details here](https://codehawks.cyfrin.io/c/2023-10-PasswordStore)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 2
   - Medium: 0
   - Low: 1


# High Risk Findings

## <a id='H-01'></a>H-01. Anyone can set the password by calling `PasswordStore::setPassword`

_Submitted by [0xaleko](https://profiles.cyfrin.io/u/undefined), [irondevx](https://profiles.cyfrin.io/u/undefined), [cosine](https://profiles.cyfrin.io/u/undefined), [vielite](https://profiles.cyfrin.io/u/undefined), [MysticalPistachio](https://profiles.cyfrin.io/u/undefined), [kamuik16](https://profiles.cyfrin.io/u/undefined), [ret2basic](https://profiles.cyfrin.io/u/undefined), [0x0noob](https://profiles.cyfrin.io/u/undefined), [anjalit](https://profiles.cyfrin.io/u/undefined), [yeahchibyke](https://profiles.cyfrin.io/u/undefined), [azmaeengh](https://profiles.cyfrin.io/u/undefined), [nisedo](https://profiles.cyfrin.io/u/undefined), [0xdimo](https://profiles.cyfrin.io/u/undefined), [kevinkkien](https://profiles.cyfrin.io/u/undefined), [Chandr](https://profiles.cyfrin.io/u/undefined), [alsirang](https://profiles.cyfrin.io/u/undefined), [notvalidaccount](https://profiles.cyfrin.io/u/undefined), [sandman](https://profiles.cyfrin.io/u/undefined), [0xbigwing](https://profiles.cyfrin.io/u/undefined), [funkornaut](https://profiles.cyfrin.io/u/undefined), [atrixs](https://profiles.cyfrin.io/u/undefined), [joesan](https://profiles.cyfrin.io/u/undefined), [zac369](https://profiles.cyfrin.io/u/undefined), [priker](https://profiles.cyfrin.io/u/undefined), [Magnetto](https://profiles.cyfrin.io/u/undefined), [gin](https://profiles.cyfrin.io/u/undefined), [falconhoof](https://profiles.cyfrin.io/u/undefined), [abhishekthakur](https://profiles.cyfrin.io/u/undefined), [timenov](https://profiles.cyfrin.io/u/undefined), [0xkeesmark](https://profiles.cyfrin.io/u/undefined), [darksnow](https://profiles.cyfrin.io/u/undefined), [Rotcivegaf](https://profiles.cyfrin.io/u/undefined), [Nachoddiaz](https://profiles.cyfrin.io/u/undefined), [Proxy](https://profiles.cyfrin.io/u/undefined), [mrpotatomagic](https://profiles.cyfrin.io/u/undefined), [0x6a70](https://profiles.cyfrin.io/u/undefined), [0xAbinash](https://profiles.cyfrin.io/u/undefined), [tsar](https://profiles.cyfrin.io/u/undefined), [anarcheuz](https://profiles.cyfrin.io/u/undefined), [bLnk](https://profiles.cyfrin.io/u/undefined), [aaa](https://profiles.cyfrin.io/u/undefined), [adilc](https://profiles.cyfrin.io/u/undefined), [ABA](https://profiles.cyfrin.io/u/undefined), [ElHaj](https://profiles.cyfrin.io/u/undefined), [atoko](https://profiles.cyfrin.io/u/undefined), [asamd](https://profiles.cyfrin.io/u/undefined), [aamirusmani1552](https://profiles.cyfrin.io/u/undefined), [pacelli](https://profiles.cyfrin.io/u/undefined), [gabr1sr](https://profiles.cyfrin.io/u/undefined), [x0rd3v1l](https://profiles.cyfrin.io/u/undefined), [caxva](https://profiles.cyfrin.io/u/undefined), [bytes1](https://profiles.cyfrin.io/u/undefined), [Mj0ln1r](https://profiles.cyfrin.io/u/undefined), [SaudxInu](https://profiles.cyfrin.io/u/undefined), [light](https://profiles.cyfrin.io/u/undefined), [0xhuy0512](https://profiles.cyfrin.io/u/undefined), [ivanfitro](https://profiles.cyfrin.io/u/undefined), [Testerbot](https://profiles.cyfrin.io/u/undefined), [happyformerlawyer](https://profiles.cyfrin.io/u/undefined), [lordforever](https://profiles.cyfrin.io/u/undefined), [laithx9](https://profiles.cyfrin.io/u/undefined), [davide](https://profiles.cyfrin.io/u/undefined), [0xloscar01](https://profiles.cyfrin.io/u/undefined), [ararara](https://profiles.cyfrin.io/u/undefined), [yongtaufoo](https://profiles.cyfrin.io/u/undefined), [rufflabs](https://profiles.cyfrin.io/u/undefined), [longzai](https://profiles.cyfrin.io/u/undefined), [Andrew](https://profiles.cyfrin.io/u/undefined), [0xjacopod](https://profiles.cyfrin.io/u/undefined), [danielvo102](https://profiles.cyfrin.io/u/undefined), [0xabhayy](https://profiles.cyfrin.io/u/undefined), [dalaillama](https://profiles.cyfrin.io/u/undefined), [kuldeepyeware](https://profiles.cyfrin.io/u/undefined), [tpiliposian](https://profiles.cyfrin.io/u/undefined), [musashi](https://profiles.cyfrin.io/u/undefined), [Aitor](https://profiles.cyfrin.io/u/undefined), [aethrouzz](https://profiles.cyfrin.io/u/undefined), [Arav](https://profiles.cyfrin.io/u/undefined), [kiteweb3](https://profiles.cyfrin.io/u/undefined), [llill](https://profiles.cyfrin.io/u/undefined), [polaris_tow](https://profiles.cyfrin.io/u/undefined), [okolicodes](https://profiles.cyfrin.io/u/undefined), [merklebonsai](https://profiles.cyfrin.io/u/undefined), [slasheur](https://profiles.cyfrin.io/u/undefined), [luka](https://profiles.cyfrin.io/u/undefined), [MikeDougherty](https://profiles.cyfrin.io/u/undefined), [polarzero](https://profiles.cyfrin.io/u/undefined), [ZedBlockchain](https://profiles.cyfrin.io/u/undefined), [0xfave](https://profiles.cyfrin.io/u/undefined), [icebear](https://profiles.cyfrin.io/u/undefined), [modey](https://profiles.cyfrin.io/u/undefined), [00decree](https://profiles.cyfrin.io/u/undefined), [lealCodes](https://profiles.cyfrin.io/u/undefined), [Niki](https://profiles.cyfrin.io/u/undefined), [silverwind](https://profiles.cyfrin.io/u/undefined), [ljj](https://profiles.cyfrin.io/u/undefined), [0xJimbo](https://profiles.cyfrin.io/u/undefined), [iLoveMiaGoth](https://profiles.cyfrin.io/u/undefined), [denzi](https://profiles.cyfrin.io/u/undefined), [CryptoAudit](https://profiles.cyfrin.io/u/undefined), [sonny2k](https://profiles.cyfrin.io/u/undefined), [numbernine](https://profiles.cyfrin.io/u/undefined), [0xVinylDavyl](https://profiles.cyfrin.io/u/undefined), [blocktivist](https://profiles.cyfrin.io/u/undefined), [0xla](https://profiles.cyfrin.io/u/undefined), [BTinoRi](https://profiles.cyfrin.io/u/undefined), [0xtheblackpanther](https://profiles.cyfrin.io/u/undefined), [WangSecurity](https://profiles.cyfrin.io/u/undefined), [0xGhali](https://profiles.cyfrin.io/u/undefined), [0x392](https://profiles.cyfrin.io/u/undefined), [merlinboii](https://profiles.cyfrin.io/u/undefined), [jnrlouis](https://profiles.cyfrin.io/u/undefined), [acu](https://profiles.cyfrin.io/u/undefined), [Eric](https://profiles.cyfrin.io/u/undefined), [giraffe0x](https://profiles.cyfrin.io/u/undefined), [trauki](https://profiles.cyfrin.io/u/undefined), [nervouspika](https://profiles.cyfrin.io/u/undefined), [zxarcs](https://profiles.cyfrin.io/u/undefined), [ericselvig](https://profiles.cyfrin.io/u/undefined), [shikhar229169](https://profiles.cyfrin.io/u/undefined), [Osora9](https://profiles.cyfrin.io/u/undefined), [eeshenggoh](https://profiles.cyfrin.io/u/undefined), [0xbjorn](https://profiles.cyfrin.io/u/undefined), [gusredo](https://profiles.cyfrin.io/u/undefined), [0xads90](https://profiles.cyfrin.io/u/undefined), [victor](https://profiles.cyfrin.io/u/undefined), [hueber](https://profiles.cyfrin.io/u/undefined), [robbiesumner](https://profiles.cyfrin.io/u/undefined), [dcheng](https://profiles.cyfrin.io/u/undefined), [ZdravkoHr](https://profiles.cyfrin.io/u/undefined), [nmirchev8](https://profiles.cyfrin.io/u/undefined), [harpaljadeja](https://profiles.cyfrin.io/u/undefined), [0xprinc](https://profiles.cyfrin.io/u/undefined), [zach030](https://profiles.cyfrin.io/u/undefined), [zhuying](https://profiles.cyfrin.io/u/undefined), [tinotendajoe01](https://profiles.cyfrin.io/u/undefined), [rapstyle](https://profiles.cyfrin.io/u/undefined), [EchoSpr](https://profiles.cyfrin.io/u/undefined), [SargeSMITH](https://profiles.cyfrin.io/u/undefined), [mld](https://profiles.cyfrin.io/u/undefined), [dougo](https://profiles.cyfrin.io/u/undefined), [ugrru](https://profiles.cyfrin.io/u/undefined), [0xsagetony](https://profiles.cyfrin.io/u/undefined), [engrpips](https://profiles.cyfrin.io/u/undefined), [ahmedjb](https://profiles.cyfrin.io/u/undefined), [jerseyjoewalcott](https://profiles.cyfrin.io/u/undefined), [0xrochimaru](https://profiles.cyfrin.io/u/undefined), [CryptoThemeX](https://profiles.cyfrin.io/u/undefined), [zuhaibmohd](https://profiles.cyfrin.io/u/undefined), [0xSimeon](https://profiles.cyfrin.io/u/undefined), [etherhood](https://profiles.cyfrin.io/u/undefined), [PeCo999](https://profiles.cyfrin.io/u/undefined), [kali](https://profiles.cyfrin.io/u/undefined), [intellygentle](https://profiles.cyfrin.io/u/undefined), [ThermoHash](https://profiles.cyfrin.io/u/undefined), [karthick](https://profiles.cyfrin.io/u/undefined), [0xpinto](https://profiles.cyfrin.io/u/undefined), [0x0115](https://profiles.cyfrin.io/u/undefined), [krisrenzo](https://profiles.cyfrin.io/u/undefined), [efecarranza](https://profiles.cyfrin.io/u/undefined), [wallebach](https://profiles.cyfrin.io/u/undefined), [trav](https://profiles.cyfrin.io/u/undefined), [0xLuke4G1](https://profiles.cyfrin.io/u/undefined), [0xsandy](https://profiles.cyfrin.io/u/undefined), [0xepley](https://codehawks.cyfrin.io/team/clkjtgvih0001jt088aqegxjj), [0xfuluz](https://profiles.cyfrin.io/u/undefined), [maanvad3r](https://profiles.cyfrin.io/u/undefined), [sach1r0](https://profiles.cyfrin.io/u/undefined), [uint256vieet](https://profiles.cyfrin.io/u/undefined), [0xspryon](https://profiles.cyfrin.io/u/undefined), [stakog](https://profiles.cyfrin.io/u/undefined), [sabit](https://profiles.cyfrin.io/u/undefined), [pratred](https://profiles.cyfrin.io/u/undefined), [equious](https://profiles.cyfrin.io/u/undefined), [PTolev](https://profiles.cyfrin.io/u/undefined), [Obin](https://profiles.cyfrin.io/u/undefined), [crypt0mate](https://profiles.cyfrin.io/u/undefined), [David77](https://profiles.cyfrin.io/u/undefined), [0x4non](https://profiles.cyfrin.io/u/undefined), [836541](https://profiles.cyfrin.io/u/undefined), [KuroHashDit](https://profiles.cyfrin.io/u/undefined), [DuncanDuMond](https://profiles.cyfrin.io/u/undefined), [2pats](https://profiles.cyfrin.io/u/undefined), [topmark](https://profiles.cyfrin.io/u/undefined), [charalab0ts](https://profiles.cyfrin.io/u/undefined), [0xVicN](https://profiles.cyfrin.io/u/undefined), [setstacklist](https://profiles.cyfrin.io/u/undefined), [bhvrvt](https://profiles.cyfrin.io/u/undefined), [ke1cam](https://profiles.cyfrin.io/u/undefined), [mrjorystewartbaxter](https://profiles.cyfrin.io/u/undefined), [Skalv](https://profiles.cyfrin.io/u/undefined), [syahirAmali](https://profiles.cyfrin.io/u/undefined), [naman1729](https://profiles.cyfrin.io/u/undefined), [amar](https://profiles.cyfrin.io/u/undefined), [0x013ev](https://profiles.cyfrin.io/u/undefined), [karanctf](https://profiles.cyfrin.io/u/undefined), [remedcu](https://profiles.cyfrin.io/u/undefined), [zen4269](https://profiles.cyfrin.io/u/undefined), [danlipert](https://profiles.cyfrin.io/u/undefined), [ironcladmerc](https://profiles.cyfrin.io/u/undefined), [lionel](https://profiles.cyfrin.io/u/undefined), [0xswahili](https://profiles.cyfrin.io/u/undefined), [Marcologonz](https://profiles.cyfrin.io/u/undefined), [Phantomsands](https://profiles.cyfrin.io/u/undefined), [mahivasisth](https://profiles.cyfrin.io/u/undefined), [SubhradeepS158](https://profiles.cyfrin.io/u/undefined), [ecwarrior13](https://profiles.cyfrin.io/u/undefined), [n4thedev01](https://profiles.cyfrin.io/u/undefined), [bronzepickaxe](https://profiles.cyfrin.io/u/undefined), [ETHANHUNTIMF99](https://profiles.cyfrin.io/u/undefined), [thetechnofeak](https://profiles.cyfrin.io/u/undefined), [ihtishamsudo](https://profiles.cyfrin.io/u/undefined), [aviksaikat](https://profiles.cyfrin.io/u/undefined), [Dutch](https://profiles.cyfrin.io/u/undefined), [0xMUSA1337](https://profiles.cyfrin.io/u/undefined), [0xgd](https://profiles.cyfrin.io/u/undefined), [luiscfaria](https://profiles.cyfrin.io/u/undefined), [jefestar](https://profiles.cyfrin.io/u/undefined), [coffee](https://profiles.cyfrin.io/u/undefined), [m1nd0v3rfl0w](https://profiles.cyfrin.io/u/undefined), [alymurtazamemon](https://profiles.cyfrin.io/u/undefined), [boredpukar](https://profiles.cyfrin.io/u/undefined), [editdev](https://profiles.cyfrin.io/u/undefined), [ro1sharkm](https://profiles.cyfrin.io/u/undefined), [Heba](https://profiles.cyfrin.io/u/undefined), [ezerez](https://profiles.cyfrin.io/u/undefined), [Damilare](https://profiles.cyfrin.io/u/undefined), [Prabhas](https://profiles.cyfrin.io/u/undefined), [klaus](https://profiles.cyfrin.io/u/undefined), [dadev](https://profiles.cyfrin.io/u/undefined), [silvana](https://profiles.cyfrin.io/u/undefined), [Awacs](https://profiles.cyfrin.io/u/undefined), [codyx](https://profiles.cyfrin.io/u/undefined), [theirrationalone](https://profiles.cyfrin.io/u/undefined), [0xnilesh](https://profiles.cyfrin.io/u/undefined), [ciaranightingale](https://profiles.cyfrin.io/u/undefined), [0xouooo](https://profiles.cyfrin.io/u/undefined), [MufDSol](https://profiles.cyfrin.io/u/undefined), [0xblackskull](https://profiles.cyfrin.io/u/undefined), [emanherawy](https://profiles.cyfrin.io/u/undefined), [0xaraj](https://profiles.cyfrin.io/u/undefined), [bube](https://profiles.cyfrin.io/u/undefined), [0x8e88](https://profiles.cyfrin.io/u/undefined), [sm4rty](https://profiles.cyfrin.io/u/undefined), [0xKriLuv](https://profiles.cyfrin.io/u/undefined), [mgf15](https://profiles.cyfrin.io/u/undefined), [Avi17](https://profiles.cyfrin.io/u/undefined), [toddteller](https://profiles.cyfrin.io/u/undefined), [0xaman](https://profiles.cyfrin.io/u/undefined), [wafflemakr](https://profiles.cyfrin.io/u/undefined), [zadev](https://profiles.cyfrin.io/u/undefined), [maroutis](https://profiles.cyfrin.io/u/undefined), [TorpedopistolIxc41](https://profiles.cyfrin.io/u/undefined), [sobieski](https://profiles.cyfrin.io/u/undefined), [maplerichie](https://profiles.cyfrin.io/u/undefined), [Ekiio](https://profiles.cyfrin.io/u/undefined), [cryptonoob](https://profiles.cyfrin.io/u/undefined), [cRat1st0s](https://profiles.cyfrin.io/u/undefined), [Nayan](https://profiles.cyfrin.io/u/undefined), [JCM](https://profiles.cyfrin.io/u/undefined), [0xDrMoon](https://profiles.cyfrin.io/u/undefined), [touthang](https://profiles.cyfrin.io/u/undefined), [Chput](https://profiles.cyfrin.io/u/undefined), [tutkata](https://profiles.cyfrin.io/u/undefined), [Nocturnus](https://profiles.cyfrin.io/u/undefined), [TumeloCrypto](https://profiles.cyfrin.io/u/undefined), [draiakoo](https://profiles.cyfrin.io/u/undefined), [damoklov](https://profiles.cyfrin.io/u/undefined), [0xscsamurai](https://profiles.cyfrin.io/u/undefined), [n0kto](https://profiles.cyfrin.io/u/undefined), [praise03](https://profiles.cyfrin.io/u/undefined), [kose](https://profiles.cyfrin.io/u/undefined), [0xrex](https://profiles.cyfrin.io/u/undefined), [benbo](https://profiles.cyfrin.io/u/undefined), [Kelvineth](https://profiles.cyfrin.io/u/undefined), [rocknet](https://profiles.cyfrin.io/u/undefined), [0xraion](https://profiles.cyfrin.io/u/undefined), [codelock](https://profiles.cyfrin.io/u/undefined), [DappDojo](https://profiles.cyfrin.io/u/undefined), [Omeguhh](https://profiles.cyfrin.io/u/undefined), [0x0bservor](https://profiles.cyfrin.io/u/undefined), [0xnevi](https://profiles.cyfrin.io/u/undefined), [daryletan](https://profiles.cyfrin.io/u/undefined), [UnvirsalX](https://profiles.cyfrin.io/u/undefined), [0xzyphernix](https://profiles.cyfrin.io/u/undefined), [innertia](https://profiles.cyfrin.io/u/undefined), [ivaniuss](https://profiles.cyfrin.io/u/undefined), [Nobita](https://profiles.cyfrin.io/u/undefined), [timo](https://profiles.cyfrin.io/u/undefined), [jasmine](https://profiles.cyfrin.io/u/undefined), [usmanfarooq90](https://profiles.cyfrin.io/u/undefined), [whiteh4t9527](https://profiles.cyfrin.io/u/undefined), [serialcoder](https://profiles.cyfrin.io/u/undefined), [0xdangit](https://profiles.cyfrin.io/u/undefined), [firmanregar](https://profiles.cyfrin.io/u/undefined), [patrooney](https://profiles.cyfrin.io/u/undefined), [Oozman](https://profiles.cyfrin.io/u/undefined), [dianivanov](https://profiles.cyfrin.io/u/undefined), [0x11singh99](https://profiles.cyfrin.io/u/undefined), [0xlouistsai](https://profiles.cyfrin.io/u/undefined), [azanux](https://profiles.cyfrin.io/u/undefined), [djanerch](https://profiles.cyfrin.io/u/undefined), [0xAxe](https://profiles.cyfrin.io/u/undefined), [0xYudhishthra](https://profiles.cyfrin.io/u/undefined), [printfjoby](https://profiles.cyfrin.io/u/undefined), [0xF001](https://profiles.cyfrin.io/u/undefined), [radeveth](https://profiles.cyfrin.io/u/undefined), [ParthMandale](https://profiles.cyfrin.io/u/undefined). Selected submission by: [ciaranightingale](https://profiles.cyfrin.io/u/undefined)._      
            
### Relevant GitHub Links

https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L31C5-L40C6

## Summary

The `PasswordStore` contract assumes that only the owner can set the password. The `setPassword()` function modifies the `s_password` storage variable, where the password is set, but doesn't include access control meaning that anyone, including a malicious actor, can reset the owner's password.

## Vulnerability Details

This vulnerability exists in the `PasswordStore::setPassword` function in the `PasswordStore.sol` file starting on [line 26](https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L26).

The `setPassword()` function includes no access controls meaning that anyone can call it and modify the password:

```solidity
/*
     * @notice This function allows only the owner to set a new password.
     * @param newPassword The new password to set.
     */
    function setPassword(string memory newPassword) external {
        s_password = newPassword;
        emit SetNetPassword();
    }
```

To restrict who can modify the password, there needs to be a check that the function caller, the `msg.sender`, is the owner of the contract.

## Impact

A possible potential use case for this contract is that the owner, the address stored in the storage variable `s_owner`, wants to use the contract as a password manager. If someone else can modify the password then the contract will not return the password they intended to store. This negates the intended use of the contract.

Since anyone, inluding malicious actors, can set the password, this opens up to the possibility that, depending on the context, these unsantisied and potentially malicious strings could be dangerous.

As per the following NatSpec comment: `This function allows only the owner to set a new password`, only the owner being able to set the password is the core assumtion, and functionality that does not hold, this is a high severity vulnerability.

## Proof of Concept

### Working Test Case

The `makeAddr` helper function is used to setup an `attacker` address to call the `setPasword()` function:

```diff
contract PasswordStoreTest is Test {
    PasswordStore public passwordStore;
    DeployPasswordStore public deployer;
    address public owner;
+   address public attacker;

    function setUp() public {
        deployer = new DeployPasswordStore();
        passwordStore = deployer.run();
        owner = msg.sender;
        // attacker address
+       attacker = makeAddr("attacker");
    }
}
```

The following test, sets the password to `"attackerPassword"` using the attacker address. When run, this test will pass, demonstrating that the attacker can set the password:

```solidity
    function test_poc_non_owner_set_password() public {
        // initiate the transaction from the non-owner attacker address
        vm.prank(attacker);
        string memory newPassword = "attackerPassword";
        // attacker attempts to set the password
        passwordStore.setPassword(newPassword);
        console.log("The attacker successfully set the password:" newPassword);
    }
```

Run the test:

```bash
forge test --mt test_poc_non_owner_set_password -vvvv
```

Which yields the following output:

```bash
unning 1 test for test/PasswordStore.t.sol:PasswordStoreTest
[PASS] test_poc_non_owner_set_password() (gas: 20776)
Logs:
  The attacker successfully set the password: attackerPassword

Traces:
  [20776] PasswordStoreTest::test_poc_non_owner_set_password()
    ├─ [0] VM::prank(attacker: [0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e])
    │   └─ ← ()
    ├─ [6686] PasswordStore::setPassword(attackerPassword)
    │   ├─ emit SetNetPassword()
    │   └─ ← ()
    ├─ [0] console::log(The attacker successfully set the password: attackerPassword) [staticcall]
    │   └─ ← ()
    └─ ← ()

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.36ms
```

## Recommended Mitigation

Include access control to restrict who can call the `setPassword` function to be only the owner: `s_owner`. This can be achieved in two ways:

1. Using an `if` statement, as used in the `getPassword` function, and revert with the `PasswordStore__NotOwer()` custom error if the address calling the function is not the owner:

```diff
    function setPassword(string memory newPassword) external {
        // @audit check that the function caller is the owner of the contract
+        if (msg.sender != s_owner) {
+            revert PasswordStore__NotOwner();
+        }
        s_password = newPassword;
        emit SetNetPassword();
    }
```

2. Using an access modifier e.g. OpenZeppelin's `onlyOwner`. To use this modifier, the `PasswordStore` contract will need to inherit from OpenZeppelin's `Ownable` contract and call it's constructor inside the constructor of `PasswordStore`:

```diff
 // @audit import the ownable contract from OpenZeppelin
+ import "@openzeppelin/contracts/ownership/Ownable.sol";

 // @audit inherit from the Ownable contract
+ contract PasswordStore is Ownable{
    error PasswordStore__NotOwner();

    address private s_owner;
    string private s_password;

    event SetNetPassword();

+    constructor() Ownable() {
        s_owner = msg.sender;
    }
}
```

As per the OpenZeppelin documentation, by default, the `owner` of an `Ownable` contract is the account that deployed it, meaning that the `s_owner` state variable can be removed.

Using `onlyOwner` modifier adds logic to check that the `msg.sender` is the `owner` of the contract before executing the function's logic:

```diff
    /*
     * @notice This function allows only the owner to set a new password.
     * @param newPassword The new password to set.
     */
+   function setPassword(string memory newPassword) external onlyOwner {
        s_password = newPassword;
        emit SetNetPassword();
    }
```

## Tools Used

- [Forge](https://book.getfoundry.sh/forge/)

## <a id='H-02'></a>H-02. Owner's password stored in the `s_password` state variable is not a secret and can be seen by everyone

_Submitted by [cosine](https://profiles.cyfrin.io/u/undefined), [vielite](https://profiles.cyfrin.io/u/undefined), [ret2basic](https://profiles.cyfrin.io/u/undefined), [0xdimo](https://profiles.cyfrin.io/u/undefined), [anarcheuz](https://profiles.cyfrin.io/u/undefined), [kevinkkien](https://profiles.cyfrin.io/u/undefined), [x0rd3v1l](https://profiles.cyfrin.io/u/undefined), [nisedo](https://profiles.cyfrin.io/u/undefined), [priker](https://profiles.cyfrin.io/u/undefined), [Magnetto](https://profiles.cyfrin.io/u/undefined), [Chandr](https://profiles.cyfrin.io/u/undefined), [atrixs](https://profiles.cyfrin.io/u/undefined), [zac369](https://profiles.cyfrin.io/u/undefined), [gin](https://profiles.cyfrin.io/u/undefined), [timenov](https://profiles.cyfrin.io/u/undefined), [0xkeesmark](https://profiles.cyfrin.io/u/undefined), [funkornaut](https://profiles.cyfrin.io/u/undefined), [Nachoddiaz](https://profiles.cyfrin.io/u/undefined), [abhishekthakur](https://profiles.cyfrin.io/u/undefined), [adilc](https://profiles.cyfrin.io/u/undefined), [darksnow](https://profiles.cyfrin.io/u/undefined), [Proxy](https://profiles.cyfrin.io/u/undefined), [akhilmanga](https://profiles.cyfrin.io/u/undefined), [0x6a70](https://profiles.cyfrin.io/u/undefined), [mrpotatomagic](https://profiles.cyfrin.io/u/undefined), [aaa](https://profiles.cyfrin.io/u/undefined), [pyro](https://profiles.cyfrin.io/u/undefined), [bLnk](https://profiles.cyfrin.io/u/undefined), [tsar](https://profiles.cyfrin.io/u/undefined), [ABA](https://profiles.cyfrin.io/u/undefined), [ElHaj](https://profiles.cyfrin.io/u/undefined), [aamirusmani1552](https://profiles.cyfrin.io/u/undefined), [asamd](https://profiles.cyfrin.io/u/undefined), [light](https://profiles.cyfrin.io/u/undefined), [SaudxInu](https://profiles.cyfrin.io/u/undefined), [gabr1sr](https://profiles.cyfrin.io/u/undefined), [0xhuy0512](https://profiles.cyfrin.io/u/undefined), [ivanfitro](https://profiles.cyfrin.io/u/undefined), [Testerbot](https://profiles.cyfrin.io/u/undefined), [pacelli](https://profiles.cyfrin.io/u/undefined), [happyformerlawyer](https://profiles.cyfrin.io/u/undefined), [lordforever](https://profiles.cyfrin.io/u/undefined), [0xethanol](https://profiles.cyfrin.io/u/undefined), [davide](https://profiles.cyfrin.io/u/undefined), [ararara](https://profiles.cyfrin.io/u/undefined), [0xloscar01](https://profiles.cyfrin.io/u/undefined), [yongtaufoo](https://profiles.cyfrin.io/u/undefined), [longzai](https://profiles.cyfrin.io/u/undefined), [0xjacopod](https://profiles.cyfrin.io/u/undefined), [0xabhayy](https://profiles.cyfrin.io/u/undefined), [dalaillama](https://profiles.cyfrin.io/u/undefined), [cem](https://profiles.cyfrin.io/u/undefined), [tpiliposian](https://profiles.cyfrin.io/u/undefined), [Arav](https://profiles.cyfrin.io/u/undefined), [aethrouzz](https://profiles.cyfrin.io/u/undefined), [Aitor](https://profiles.cyfrin.io/u/undefined), [kiteweb3](https://profiles.cyfrin.io/u/undefined), [llill](https://profiles.cyfrin.io/u/undefined), [m4k2](https://profiles.cyfrin.io/u/undefined), [polaris_tow](https://profiles.cyfrin.io/u/undefined), [slasheur](https://profiles.cyfrin.io/u/undefined), [musashi](https://profiles.cyfrin.io/u/undefined), [merklebonsai](https://profiles.cyfrin.io/u/undefined), [luka](https://profiles.cyfrin.io/u/undefined), [polarzero](https://profiles.cyfrin.io/u/undefined), [SHA256](https://profiles.cyfrin.io/u/undefined), [ZedBlockchain](https://profiles.cyfrin.io/u/undefined), [icebear](https://profiles.cyfrin.io/u/undefined), [00decree](https://profiles.cyfrin.io/u/undefined), [silverwind](https://profiles.cyfrin.io/u/undefined), [iLoveMiaGoth](https://profiles.cyfrin.io/u/undefined), [lealCodes](https://profiles.cyfrin.io/u/undefined), [ljj](https://profiles.cyfrin.io/u/undefined), [0xVinylDavyl](https://profiles.cyfrin.io/u/undefined), [sonny2k](https://profiles.cyfrin.io/u/undefined), [tychaios](https://profiles.cyfrin.io/u/undefined), [blocktivist](https://profiles.cyfrin.io/u/undefined), [0xtheblackpanther](https://profiles.cyfrin.io/u/undefined), [merlinboii](https://profiles.cyfrin.io/u/undefined), [0xGhali](https://profiles.cyfrin.io/u/undefined), [0xJimbo](https://profiles.cyfrin.io/u/undefined), [acu](https://profiles.cyfrin.io/u/undefined), [jnrlouis](https://profiles.cyfrin.io/u/undefined), [robbiesumner](https://profiles.cyfrin.io/u/undefined), [Eric](https://profiles.cyfrin.io/u/undefined), [giraffe0x](https://profiles.cyfrin.io/u/undefined), [ericselvig](https://profiles.cyfrin.io/u/undefined), [nervouspika](https://profiles.cyfrin.io/u/undefined), [alphabuddha1357](https://profiles.cyfrin.io/u/undefined), [Andrew](https://profiles.cyfrin.io/u/undefined), [shikhar229169](https://profiles.cyfrin.io/u/undefined), [eeshenggoh](https://profiles.cyfrin.io/u/undefined), [0xbjorn](https://profiles.cyfrin.io/u/undefined), [auditism](https://profiles.cyfrin.io/u/undefined), [C0D30](https://profiles.cyfrin.io/u/undefined), [kamuik16](https://profiles.cyfrin.io/u/undefined), [ZdravkoHr](https://profiles.cyfrin.io/u/undefined), [nmirchev8](https://profiles.cyfrin.io/u/undefined), [stakog](https://profiles.cyfrin.io/u/undefined), [harpaljadeja](https://profiles.cyfrin.io/u/undefined), [0xdark1337](https://profiles.cyfrin.io/u/undefined), [tinotendajoe01](https://profiles.cyfrin.io/u/undefined), [SargeSMITH](https://profiles.cyfrin.io/u/undefined), [ugrru](https://profiles.cyfrin.io/u/undefined), [dcheng](https://profiles.cyfrin.io/u/undefined), [dougo](https://profiles.cyfrin.io/u/undefined), [0xsagetony](https://profiles.cyfrin.io/u/undefined), [aviksaikat](https://profiles.cyfrin.io/u/undefined), [notvalidaccount](https://profiles.cyfrin.io/u/undefined), [rufflabs](https://profiles.cyfrin.io/u/undefined), [CryptoThemeX](https://profiles.cyfrin.io/u/undefined), [zuhaibmohd](https://profiles.cyfrin.io/u/undefined), [0xSimeon](https://profiles.cyfrin.io/u/undefined), [etherhood](https://profiles.cyfrin.io/u/undefined), [ThermoHash](https://profiles.cyfrin.io/u/undefined), [0xpinto](https://profiles.cyfrin.io/u/undefined), [0x0115](https://profiles.cyfrin.io/u/undefined), [krisrenzo](https://profiles.cyfrin.io/u/undefined), [efecarranza](https://profiles.cyfrin.io/u/undefined), [EchoSpr](https://profiles.cyfrin.io/u/undefined), [0xsandy](https://profiles.cyfrin.io/u/undefined), [Nobita](https://profiles.cyfrin.io/u/undefined), [maanvad3r](https://profiles.cyfrin.io/u/undefined), [0xfuluz](https://profiles.cyfrin.io/u/undefined), [0xspryon](https://profiles.cyfrin.io/u/undefined), [pratred](https://profiles.cyfrin.io/u/undefined), [PTolev](https://profiles.cyfrin.io/u/undefined), [zxarcs](https://profiles.cyfrin.io/u/undefined), [equious](https://profiles.cyfrin.io/u/undefined), [MikeDougherty](https://profiles.cyfrin.io/u/undefined), [836541](https://profiles.cyfrin.io/u/undefined), [0x4non](https://profiles.cyfrin.io/u/undefined), [KuroHashDit](https://profiles.cyfrin.io/u/undefined), [crypt0mate](https://profiles.cyfrin.io/u/undefined), [2pats](https://profiles.cyfrin.io/u/undefined), [topmark](https://profiles.cyfrin.io/u/undefined), [0xnhattranduy](https://profiles.cyfrin.io/u/undefined), [ke1cam](https://profiles.cyfrin.io/u/undefined), [Skalv](https://profiles.cyfrin.io/u/undefined), [amar](https://profiles.cyfrin.io/u/undefined), [remedcu](https://profiles.cyfrin.io/u/undefined), [danlipert](https://profiles.cyfrin.io/u/undefined), [zen4269](https://profiles.cyfrin.io/u/undefined), [naman1729](https://profiles.cyfrin.io/u/undefined), [ironcladmerc](https://profiles.cyfrin.io/u/undefined), [DappDojo](https://profiles.cyfrin.io/u/undefined), [lionel](https://profiles.cyfrin.io/u/undefined), [Marcologonz](https://profiles.cyfrin.io/u/undefined), [gunboats](https://profiles.cyfrin.io/u/undefined), [Phantomsands](https://profiles.cyfrin.io/u/undefined), [rapstyle](https://profiles.cyfrin.io/u/undefined), [n4thedev01](https://profiles.cyfrin.io/u/undefined), [syahirAmali](https://profiles.cyfrin.io/u/undefined), [Obin](https://profiles.cyfrin.io/u/undefined), [thetechnofeak](https://profiles.cyfrin.io/u/undefined), [ihtishamsudo](https://profiles.cyfrin.io/u/undefined), [0xMUSA1337](https://profiles.cyfrin.io/u/undefined), [luiscfaria](https://profiles.cyfrin.io/u/undefined), [trauki](https://profiles.cyfrin.io/u/undefined), [Dutch](https://profiles.cyfrin.io/u/undefined), [0xgd](https://profiles.cyfrin.io/u/undefined), [devival](https://profiles.cyfrin.io/u/undefined), [Osora9](https://profiles.cyfrin.io/u/undefined), [m1nd0v3rfl0w](https://profiles.cyfrin.io/u/undefined), [boredpukar](https://profiles.cyfrin.io/u/undefined), [alymurtazamemon](https://profiles.cyfrin.io/u/undefined), [setstacklist](https://profiles.cyfrin.io/u/undefined), [ro1sharkm](https://profiles.cyfrin.io/u/undefined), [Heba](https://profiles.cyfrin.io/u/undefined), [bronzepickaxe](https://profiles.cyfrin.io/u/undefined), [klaus](https://profiles.cyfrin.io/u/undefined), [dadev](https://profiles.cyfrin.io/u/undefined), [Prabhas](https://profiles.cyfrin.io/u/undefined), [silvana](https://profiles.cyfrin.io/u/undefined), [philfr](https://profiles.cyfrin.io/u/undefined), [codyx](https://profiles.cyfrin.io/u/undefined), [MufDSol](https://profiles.cyfrin.io/u/undefined), [ciaranightingale](https://profiles.cyfrin.io/u/undefined), [0xouooo](https://profiles.cyfrin.io/u/undefined), [theirrationalone](https://profiles.cyfrin.io/u/undefined), [0x8e88](https://profiles.cyfrin.io/u/undefined), [emanherawy](https://profiles.cyfrin.io/u/undefined), [bube](https://profiles.cyfrin.io/u/undefined), [ezerez](https://profiles.cyfrin.io/u/undefined), [0xnilesh](https://profiles.cyfrin.io/u/undefined), [sm4rty](https://profiles.cyfrin.io/u/undefined), [uint256vieet](https://profiles.cyfrin.io/u/undefined), [0xscsamurai](https://profiles.cyfrin.io/u/undefined), [0xKriLuv](https://profiles.cyfrin.io/u/undefined), [maroutis](https://profiles.cyfrin.io/u/undefined), [bytes1](https://profiles.cyfrin.io/u/undefined), [Avi17](https://profiles.cyfrin.io/u/undefined), [zadev](https://profiles.cyfrin.io/u/undefined), [sobieski](https://profiles.cyfrin.io/u/undefined), [wafflemakr](https://profiles.cyfrin.io/u/undefined), [TorpedopistolIxc41](https://profiles.cyfrin.io/u/undefined), [0xaman](https://profiles.cyfrin.io/u/undefined), [maplerichie](https://profiles.cyfrin.io/u/undefined), [Ekiio](https://profiles.cyfrin.io/u/undefined), [touthang](https://profiles.cyfrin.io/u/undefined), [Nocturnus](https://profiles.cyfrin.io/u/undefined), [cRat1st0s](https://profiles.cyfrin.io/u/undefined), [tutkata](https://profiles.cyfrin.io/u/undefined), [Damilare](https://profiles.cyfrin.io/u/undefined), [TumeloCrypto](https://profiles.cyfrin.io/u/undefined), [draiakoo](https://profiles.cyfrin.io/u/undefined), [asimaranov](https://profiles.cyfrin.io/u/undefined), [n0kto](https://profiles.cyfrin.io/u/undefined), [kose](https://profiles.cyfrin.io/u/undefined), [benbo](https://profiles.cyfrin.io/u/undefined), [Kelvineth](https://profiles.cyfrin.io/u/undefined), [rocknet](https://profiles.cyfrin.io/u/undefined), [0xraion](https://profiles.cyfrin.io/u/undefined), [codelock](https://profiles.cyfrin.io/u/undefined), [Omeguhh](https://profiles.cyfrin.io/u/undefined), [coffee](https://profiles.cyfrin.io/u/undefined), [0x0bservor](https://profiles.cyfrin.io/u/undefined), [0xnevi](https://profiles.cyfrin.io/u/undefined), [innertia](https://profiles.cyfrin.io/u/undefined), [ivaniuss](https://profiles.cyfrin.io/u/undefined), [timo](https://profiles.cyfrin.io/u/undefined), [TheCodingCanuck](https://profiles.cyfrin.io/u/undefined), [serialcoder](https://profiles.cyfrin.io/u/undefined), [whiteh4t9527](https://profiles.cyfrin.io/u/undefined), [usmanfarooq90](https://profiles.cyfrin.io/u/undefined), [0xdangit](https://profiles.cyfrin.io/u/undefined), [patrooney](https://profiles.cyfrin.io/u/undefined), [0x11singh99](https://profiles.cyfrin.io/u/undefined), [dianivanov](https://profiles.cyfrin.io/u/undefined), [Oozman](https://profiles.cyfrin.io/u/undefined), [azanux](https://profiles.cyfrin.io/u/undefined), [0xlouistsai](https://profiles.cyfrin.io/u/undefined), [brozorec](https://profiles.cyfrin.io/u/undefined), [0xAxe](https://profiles.cyfrin.io/u/undefined), [toddteller](https://profiles.cyfrin.io/u/undefined), [bhvrvt](https://profiles.cyfrin.io/u/undefined), [printfjoby](https://profiles.cyfrin.io/u/undefined), [0xYudhishthra](https://profiles.cyfrin.io/u/undefined), [radeveth](https://profiles.cyfrin.io/u/undefined). Selected submission by: [bhvrvt](https://profiles.cyfrin.io/u/undefined)._      
            
### Relevant GitHub Links

https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L14

## Summary

The protocol is using a `private` state variable to store the owner's password under the assumption that being a "private" variable its value is a secret from everyone else except the owner; which is a completely false assumption.

In Solidity, marking a variable as `private` doesn't mean that the data stored in that variable is entirely secret or private from all observers of the blockchain. While it restricts direct external access to the variable from other contracts, it's essential to understand that the data on the blockchain is inherently transparent and can be viewed by anyone. Other smart contracts and blockchain explorers can still access and read the data if they know where to look. 

'Private' in Solidity primarily provides encapsulation and access control within the contract itself, rather than offering complete data privacy on the public blockchain.

## Vulnerability Details

```solidity
string private s_password;
```

Aforementioned is the `s_password` variable which is being assumed as a secret by the protocol for it being a `private` variable. This is a completely false assumption since all data on the blockchain is public.

## Proof of Concept

### Actors:
- **Attacker**: Any non-owner malicious actor on the network. 
- **Victim**: Owner of the PasswordStore protocol.
- **Protocol**: PasswordStore is meant to allow only the owner to store and retrieve their password securely.


### Working Test Case:   
(**Note :** Though the following code fetches the Victim's password correctly in ASCII format; with my current skills in Solidity I've been struggling to make the `assertEq()` function return `true` when comparing the two strings. The problem seems to be with how the result of `abi.encodePacked()` for `anyoneCanReadPassword` variable fetched from `vm.load` has a bunch of trailing zeroes in it while the same for `victimPassword` doesn't.

Therefore my current POC proves the exploit by using `console.log` instead of `assertEq`
)   
  
Write and run the following test case in the `PasswordStore.t.sol` test file.

```solidity
function test_any_non_owner_can_see_password() public {
    string memory victimPassword = "mySecretPassword"; // Defines Victim's (Owner's) password
    vm.startPrank(owner); // Simulates Victim's address for the next call
    passwordStore.setPassword(victimPassword); // Victim sets their password

    // At this point, Victim thinks their password is now "privately" stored on the protocol and is completely secret.
    // The exploit code that now follows can be performed by just about everyone on the blockchain who are aware of the Victim's protocol and can access and read the Victim's password.

    /////////// EXPLOIT CODE performed by Attacker ///////////

    // By observing the protocol's source code at `PasswordStore.sol`, we notice that `s_password` is the second storage variable declared in the contract. Since storage slots are alloted in the order of declaration in the EVM, its slot value will be '1'
    uint256 S_PASSWORD_STORAGE_SLOT_VALUE = 1;

    // Access the protocol's storage data at slot 1
    bytes32 slotData = vm.load(
        address(passwordStore),
        bytes32(S_PASSWORD_STORAGE_SLOT_VALUE)
    );

    // Converting `bytes` data to `string`
    string memory anyoneCanReadPassword = string(
        abi.encodePacked(slotData)
    );
    // Exposes Victim's password on console
    console.log(anyoneCanReadPassword);
}

```

Make sure to run the test command with `-vv` flag to see the `Logs` in command output.    


## Impact
This vulnerability completely compromises the confidentiality of the protocol and exposes the sensitive private data of the owner of the protocol to everyone on the blockchain.

## Tools Used
Foundry

## Recommendations

All data on the blockchain is public. To store sensitive information, additional encryption or off-chain solutions should be considered. Sensitive and personal data should never be stored on the blockchain in plaintext or weakly encrypted or encoded format. 

# Medium Risk Findings



# Low Risk Findings

## <a id='L-01'></a>L-01. Initialization Timeframe Vulnerability

_Submitted by [dianivanov](https://profiles.cyfrin.io/u/undefined)._      
            
### Relevant GitHub Links

https://github.com/Cyfrin/2023-10-PasswordStore/blob/main/src/PasswordStore.sol

## Summary
The PasswordStore contract exhibits an initialization timeframe vulnerability. This means that there is a period between contract deployment and the explicit call to setPassword during which the password remains in its default state. It's essential to note that even after addressing this issue, the password's public visibility on the blockchain cannot be entirely mitigated, as blockchain data is inherently public as already stated in the "Storing password in blockchain" vulnerability.

## Vulnerability Details
The contract does not set the password during its construction (in the constructor). As a result, when the contract is initially deployed, the password remains uninitialized, taking on the default value for a string, which is an empty string.

During this initialization timeframe, the contract's password is effectively empty and can be considered a security gap.

## Impact
The impact of this vulnerability is that during the initialization timeframe, the contract's password is left empty, potentially exposing the contract to unauthorized access or unintended behavior. 

## Tools Used
No tools used. It was discovered through manual inspection of the contract.

## Recommendations
To mitigate the initialization timeframe vulnerability, consider setting a password value during the contract's deployment (in the constructor). This initial value can be passed in the constructor parameters.




    