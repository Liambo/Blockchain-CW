var Assignment = artifacts.require("Assignment");

module.exports = function(deployer) {
  deployer.deploy(Assignment("0x30c2eF9eDcb7ccf62a41D4006DF907082b2A894B", "100"));
};