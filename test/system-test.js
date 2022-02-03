const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("EthAddressWhitelist System Tests", async () => {
  let referenceImplementationAddress;
  let whitelistFactoryDeployed;
  let owner;
  let firstParty;
  let thirdParty;
  let accounts;
  let zeroAddress = "0x0000000000000000000000000000000000000000";
  let whitelistRoleBytes = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("WHITELISTER_ROLE"));
  beforeEach(async () => {
    [owner, firstParty, thirdParty, maliciousParty, ...accounts] = await ethers.getSigners();
    const EthAddressClonable = await ethers.getContractFactory("EthAddressWhitelistClonable");
    const referenceImplementation = await EthAddressClonable.deploy();
    await referenceImplementation.deployed();
    await referenceImplementation.initialize(owner.address, [owner.address, firstParty.address]);
    referenceImplementationAddress = referenceImplementation.address;
  });
  context("Reference EthAddressWhitelistClonable", async function () {
    it("Should not allow the owner address to be address(0)", async function () {
      [owner, firstParty, thirdParty, ...accounts] = await ethers.getSigners();
      const EthAddressWhitelistClonable = await ethers.getContractFactory("EthAddressWhitelistClonable");
      const referenceImplementation = await EthAddressWhitelistClonable.deploy();
      await referenceImplementation.deployed();
      await expect(referenceImplementation.initialize(zeroAddress, [owner.address, firstParty.address])).to.be.revertedWith("_owner may not be zero address");
    });
    it("Should not allow the a whitelist address to be address(0)", async function () {
      [owner, firstParty, thirdParty, ...accounts] = await ethers.getSigners();
      const EthAddressWhitelistClonable = await ethers.getContractFactory("EthAddressWhitelistClonable");
      const referenceImplementation = await EthAddressWhitelistClonable.deploy();
      await referenceImplementation.deployed();
      await expect(referenceImplementation.initialize(owner.address, [owner.address, zeroAddress])).to.be.revertedWith("_whitelisters[i] may not be zero address");
    });
    it("Should not allow initialize to be rerun", async function () {
      [owner, firstParty, thirdParty, ...accounts] = await ethers.getSigners();
      const EthAddressWhitelistClonable = await ethers.getContractFactory("EthAddressWhitelistClonable");
      const referenceImplementation = await EthAddressWhitelistClonable.deploy();
      await referenceImplementation.deployed();
      await referenceImplementation.initialize(owner.address, [owner.address, firstParty.address]);
      await expect(referenceImplementation.initialize(owner.address, [owner.address, firstParty.address])).to.be.revertedWith("Already initialized");
    });
  });
  context("EthAddressWhitelistFactory", async function () {
    it("Should not deploy if the reference contract address is zero address", async function () {
      const EthAddressWhitelistFactory = await ethers.getContractFactory("EthAddressWhitelistFactory");
      await expect(EthAddressWhitelistFactory.deploy(zeroAddress)).to.be.revertedWith("_referenceOpenEdition can't be zero address");
    });
    it("Should successfully deploy a clone of the reference implementation", async function () {
      const EthAddressWhitelistFactory = await ethers.getContractFactory("EthAddressWhitelistFactory");
      const whitelistFactory = await EthAddressWhitelistFactory.deploy(referenceImplementationAddress);
      await whitelistFactory.deployed();

      await expect(whitelistFactory.newEthAddressWhitelist(owner.address, [owner.address, firstParty.address])).to.emit(whitelistFactory, "EthAddressWhitelistCloneDeployed");
    });
    it("Should fail to deploy a clone of the reference implementation if the owner address is zero address", async function () {
      const EthAddressWhitelistFactory = await ethers.getContractFactory("EthAddressWhitelistFactory");
      const whitelistFactory = await EthAddressWhitelistFactory.deploy(referenceImplementationAddress);
      await whitelistFactory.deployed();

      await expect(whitelistFactory.newEthAddressWhitelist(zeroAddress, [owner.address, firstParty.address])).to.be.revertedWith("_owner may not be zero address");
    });
    it("Should fail to deploy a clone of the reference implementation if a whitelister address is zero address", async function () {
      const EthAddressWhitelistFactory = await ethers.getContractFactory("EthAddressWhitelistFactory");
      const whitelistFactory = await EthAddressWhitelistFactory.deploy(referenceImplementationAddress);
      await whitelistFactory.deployed();

      await expect(whitelistFactory.newEthAddressWhitelist(owner.address, [owner.address, zeroAddress])).to.be.revertedWith("_whitelisters[i] may not be zero address");
    });
  });
  context("EthAddressWhitelistClonable", async function () {
    beforeEach(async () => {
      const EthAddressWhitelistFactory = await ethers.getContractFactory("EthAddressWhitelistFactory");
      const whitelistFactory = await EthAddressWhitelistFactory.deploy(referenceImplementationAddress);
      await whitelistFactory.deployed();
      let newWhitelistCloneTx = await whitelistFactory.newEthAddressWhitelist(owner.address, [owner.address, firstParty.address]);
      let newWhitelistCloneTxReceipt = await newWhitelistCloneTx.wait();
      whitelistFactoryDeployed = whitelistFactory;
      contractFactory = await ethers.getContractFactory("EthAddressWhitelistClonable");
      whitelistCloneDeployed = contractFactory.attach(newWhitelistCloneTxReceipt.events[3].args.cloneAddress);
    });
    it("Should not allow zero address to be whitelisted", async function () {
      await expect(whitelistCloneDeployed.connect(owner).setWhitelistStatus(zeroAddress, true)).to.be.revertedWith("Cannot whitelist zero address");
    });
    it("Should not allow an address to be whitelisted by an invalid whitelister", async function () {
      await expect(whitelistCloneDeployed.connect(maliciousParty).setWhitelistStatus(thirdParty.address, true)).to.be.revertedWith(`AccessControl: account ${maliciousParty.address.toLowerCase()} is missing role ${whitelistRoleBytes}`);
    });
    it("Should allow an address to be whitelisted by a valid whitelister", async function () {
      await expect(whitelistCloneDeployed.connect(owner).setWhitelistStatus(thirdParty.address, true)).to.emit(whitelistCloneDeployed, "WhitelistStatusSet");
      expect(await whitelistCloneDeployed.isWhitelisted(thirdParty.address)).to.equal(true);
    });
    it("Should allow an address to have a whitelist status toggled by a valid whitelister", async function () {
      await expect(whitelistCloneDeployed.connect(owner).setWhitelistStatus(thirdParty.address, true)).to.emit(whitelistCloneDeployed, "WhitelistStatusSet");
      expect(await whitelistCloneDeployed.isWhitelisted(thirdParty.address)).to.equal(true);
      await expect(whitelistCloneDeployed.connect(owner).setWhitelistStatus(thirdParty.address, false)).to.emit(whitelistCloneDeployed, "WhitelistStatusSet");
      expect(await whitelistCloneDeployed.isWhitelisted(thirdParty.address)).to.equal(false);
    });
  });
});
