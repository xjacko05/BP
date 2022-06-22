# Decentralized biometric authentication system
# Bachelors thesis
# by Martin Jacko (xjacko05)
# VUT FIT 2022

import os
import sys
import subprocess
import shutil
import base64
import argparse
from solcx import compile_source, install_solc
import mysql.connector
import dotenv
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from web3 import Web3
from web3.middleware import geth_poa_middleware


def badExit():
    print('ERROR')
    exit(1)

def deleteBlockchainData():
    currdirs = [f.path for f in os.scandir(os.getcwd() + '\\..\\nodes') if f.is_dir()]
    for dir in currdirs:
        subdirs = [f.path for f in os.scandir(dir) if f.is_dir()]
        for subdir in subdirs:
            if 'geth' in subdir:
                shutil.rmtree(subdir)

def blockchainStart():
    p = subprocess.Popen(['powershell.exe', os.getcwd() + '\\' + os.environ['BLOCKCHAIN_INIT_FILE']], stdout=sys.stdout)
    p.communicate()

def generateKeys(size):
    key = RSA.generate(size)
    pub = open('key_pub.pem','wb')
    pub.write(key.publickey().export_key('PEM'))
    sec = open('key_sec.pem','wb')
    sec.write(key.export_key('PEM'))

def loadKey(filename):
    KeyFile = open(filename)
    key = RSA.import_key(KeyFile.read())
    KeyFile.close()
    return key

def decryptData(encData: bytes, RSAkey: RSA.RsaKey):
    encData = base64.b64decode(encData)
    RSAkeySize = RSAkey.size_in_bytes()
    encAESkey = encData[:RSAkeySize]
    AESnonce = encData[RSAkeySize:RSAkeySize+16]
    encTemplateDigest = encData[RSAkeySize+16:RSAkeySize+32]
    encTemplate = encData[RSAkeySize+32:]

    cipherRSA = PKCS1_OAEP.new(RSAkey)
    try:
        AESkey = cipherRSA.decrypt(encAESkey)
    except:
        print('Data decryption(RSA) failed - incorrect key')
        badExit()
    
    cipherAES = AES.new(AESkey, AES.MODE_EAX, AESnonce)

    try:
        data = cipherAES.decrypt_and_verify(encTemplate, encTemplateDigest)
    except:
        print('Data decryption(AES) failed')
        badExit()

    return data

def encryptData(data: bytes, RSAkey: RSA.RsaKey):
    cipherRSA = PKCS1_OAEP.new(RSAkey)

    AESkey = Random.get_random_bytes(16)
    cipherAES = AES.new(AESkey, AES.MODE_EAX)

    encAESkey = cipherRSA.encrypt(AESkey)
    encTemplate, encTemplateDigest = cipherAES.encrypt_and_digest(data)

    return base64.b64encode(encAESkey + cipherAES.nonce + encTemplateDigest + encTemplate)

def databaseConnnect():
    return mysql.connector.connect(
    host = os.environ['DB_ADDRESS'],
    port = os.environ['DB_PORT'],
    database = os.environ['DB_NAME'],
    user = os.environ['DB_USER'],
    password = os.environ['DB_PW']
    )

def databaseSetup():
    dbDropFile = open(os.environ['DB_DROP'], 'r')
    dbDrop = dbDropFile.read()
    dbDropFile.close()
    dbSetupFile = open(os.environ['DB_INIT'], 'r')
    dbSetup = dbSetupFile.read()
    dbSetupFile.close()

    dataBase = databaseConnnect()
    cursor = dataBase.cursor()

    cursor.execute(dbDrop)
    dataBase.commit()
    cursor.execute(dbSetup)
    dataBase.commit()

    cursor.close()
    dataBase.close()

def databasePush(key: RSA.RsaKey, data: bytes):
    dataBase = databaseConnnect()
    cursor = dataBase.cursor()
    cursor.execute("""INSERT INTO FPtemplates (pubkey, template) VALUES (%s, %s)""", (key.export_key(format='DER'), data))
    dataBase.commit()
    cursor.close()
    dataBase.close()

def databasePull(key: RSA.RsaKey):
    dataBase = databaseConnnect()
    cursor = dataBase.cursor()
    cursor.execute("""SELECT template FROM FPtemplates WHERE pubkey = %s""", [key.export_key(format='DER')])
    data = cursor.fetchone()
    cursor.fetchall()
    dataBase.commit()
    cursor.close()
    dataBase.close()
    if data:
        return data[0]
    else:
        return None

def databaseDelete(key: RSA.RsaKey):
    dataBase = databaseConnnect()
    cursor = dataBase.cursor()
    cursor.execute("""DELETE FROM FPtemplates WHERE pubkey = %s""", [key.export_key(format='DER')])
    dataBase.commit()
    cursor.close()
    dataBase.close()

def blockchainPull(key: RSA.RsaKey):
    w3 = Web3(Web3.HTTPProvider(os.environ['NODE_HTTP']))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    myContract = w3.eth.contract(address=os.environ['CONTRACT_ADDRESS'], abi=os.environ['CONTRACT_ABI'])
    return myContract.caller.retrieve(key.export_key('DER'))

def blockchainPush(key: RSA.RsaKey, data: bytes):
    w3 = Web3(Web3.HTTPProvider(os.environ['NODE_HTTP']))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    w3.eth.default_account = os.environ['NODE_DEFAULT_ACCOUNT']
    
    myContract = w3.eth.contract(address=os.environ['CONTRACT_ADDRESS'], abi=os.environ['CONTRACT_ABI'])
    tx_hash = myContract.functions.store(key.export_key('DER'), data.digest()).transact()
    reciept = w3.eth.wait_for_transaction_receipt(tx_hash)

def deployContract():
    w3 = Web3(Web3.HTTPProvider(os.environ['NODE_HTTP']))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    w3.eth.default_account = os.environ['NODE_DEFAULT_ACCOUNT']

    contractFile = open('storage.sol', 'r')
    contract = contractFile.read()
    contractFile.close()

    compiled = compile_source(contract)
    contract_id, contract_interface = compiled.popitem()
    os.environ['CONTRACT_ABI'] = str(contract_interface['abi']).replace('\'', '\"').replace('True', 'true').replace('False', 'false')
    dotenv.set_key(dotenv.find_dotenv(), 'CONTRACT_ABI', os.environ['CONTRACT_ABI'])
    os.environ['CONTRACT_BIN'] = contract_interface['bin']
    dotenv.set_key(dotenv.find_dotenv(), 'CONTRACT_BIN', os.environ['CONTRACT_BIN'])

    tx_hash = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin']).constructor().transact()
    contractAddress =  w3.eth.wait_for_transaction_receipt(tx_hash)['contractAddress']
    os.environ['CONTRACT_ADDRESS'] = contractAddress
    dotenv.set_key(dotenv.find_dotenv(), 'CONTRACT_ADDRESS', os.environ['CONTRACT_ADDRESS'])

def compromiseDatabase(victimPubKey, attackerPubKey, attackerTemplate):

    databaseDelete(victimPubKey)
    encData = encryptData(attackerTemplate, attackerPubKey)
    databasePush(victimPubKey, encData)


#config load
dotenv.load_dotenv()

#command and arguments parsing and setup
parser = argparse.ArgumentParser()
subparser = parser.add_subparsers(dest='command')
setup = subparser.add_parser('setup')
enroll = subparser.add_parser('enroll')
authenticate = subparser.add_parser('authenticate')
compromise = subparser.add_parser('compromise')

setup.add_argument('--keys', type=int)
setup.add_argument('--database', action='store_true')
setup.add_argument('--soliditycompiler', action='store_true')
setup.add_argument('--contract', action='store_true')
setup.add_argument('--blockchain', action='store_true')

enroll.add_argument('--template', type=str)
enroll.add_argument('--key', type=str)
enroll.add_argument('--verbose', action='store_true')

authenticate.add_argument('--template', type=str)
authenticate.add_argument('--keys', type=str, nargs=2)
authenticate.add_argument('--verbose', action='store_true')

compromise.add_argument('--victim', type=str)
compromise.add_argument('--attacker', type=str)
compromise.add_argument('--template', type=str)
compromise.add_argument('--verbose', action='store_true')

args = parser.parse_args()

print()

#setup
if args.command == 'setup':
    print('RUNNING SETUP ...')

    if args.keys:
        print('\tGenerating keys ... ', end='')
        generateKeys(args.keys)
        print('DONE')
    if args.database:
        print('\t(Re)creating database ... ', end='')
        databaseSetup()
        print('DONE')
    if args.soliditycompiler:
        print('\tInstalling solidity ... ', end='')
        install_solc(os.environ['SOLIDITY_VERSION'])
        print('DONE')
    if args.contract:
        print('\tDeploying contract ... ', end='')
        deployContract()
        print('DONE')
    if args.blockchain:
        print('\tDeleting blockchain data ... ', end='')
        deleteBlockchainData()
        print('DONE')
        print('\tStrating blockchain ... ')
        blockchainStart()
        print('DONE')

    print('SETUP DONE')

#compromise
elif args.command == 'compromise':
    print('COMPROMISING DATABASE ...')
    victimKey = loadKey(args.victim)
    attackerKey = loadKey(args.attacker)
    attackerTemplateFile = open(args.template, 'rb')
    attackerTemplate = attackerTemplateFile.read()
    attackerTemplateFile.close()
    compromiseDatabase(victimKey, attackerKey , attackerTemplate)
    print('DONE')
    if args.verbose:
        print()
        print('Victim key used:\n' + victimKey.export_key('DER').hex() + '\n')
        print('Attacker key used:\n' + attackerKey.export_key('DER').hex() + '\n')
        print('Attacker template:\n' + bytes.hex(attackerTemplate) + '\n')
else:
    if args.template:
        inputTemplateFile = open(args.template, 'rb')
    else:
        inputTemplateFile = open(os.environ['DEFAULT_TEMPLATE_FILE'], 'rb')
    inputTemplate = inputTemplateFile.read()
    inputTemplateFile.close()
    
    #enroll
    if args.command == 'enroll':
        if args.key:
            pubKey = loadKey(args.key)
        else:
            pubKey = loadKey(os.environ['DEFAULT_PUBKEY_FILE'])
        print('RUNNING ENROLLMENT ...')

        print('\tEncrypting template ... ', end='')
        encData = encryptData(inputTemplate, pubKey)
        print('DONE')

        print('\tStoring encrypted template to database ... ', end='')
        databasePush(pubKey, encData)
        print('DONE')

        print('\tStoring hash to blockchain ... ', end='')
        hash = SHA3_256.new(encData)
        blockchainPush(pubKey, hash)
        print('DONE')

        print('ENROLLMENT DONE')

        if args.verbose:
            print()
            print('Public key used:\n' + pubKey.export_key('DER').hex() + '\n')
            print('Enrolled template:\n' + bytes.hex(inputTemplate) + '\n')
            print('Hash:\n' + hash.hexdigest() + '\n')

    #authenticate
    elif args.command == 'authenticate':
        if args.keys:
            pubKey = loadKey(args.keys[0])
            secKey = loadKey(args.keys[1])
        else:
            pubKey = loadKey(os.environ['DEFAULT_PUBKEY_FILE'])
            secKey = loadKey(os.environ['DEFAULT_SECKEY_FILE'])
        print('RUNNING AUTHENTICATION ...')

        print('\tRetrieving template from database ... ', end='')
        encData = databasePull(pubKey)
        databaseHash = SHA3_256.new(encData)
        if encData:
            print('DONE')
        else:
            print('ERROR: Public key not present in database')
            badExit()

        print('\tRetrieving hash from blockchain ... ', end='')
        blockchainHash = blockchainPull(pubKey)
        if int.from_bytes(blockchainHash, 'big') != 0:
            print('DONE')
        else:
            print('ERROR: Public key not present in blockchain')
            badExit()

        print('\tChecking data integrity ... ', end='')
        if (databaseHash.digest() == blockchainHash):
            print('VALID')
        else:
            print('INVALID')

        print('\tDecrypting template ... ', end='')
        template = decryptData(encData, secKey)
        if (template != None):
            print('DONE')

        print('\tComparing templates ... ', end='')
        if (template == inputTemplate):
            print('MATCH')
        else:
            print('NO MATCH')

        print('AUTHENTICATION DONE')

        if args.verbose:
            print()
            print('Public key used:\n' + pubKey.export_key('DER').hex() + '\n')
            print('Input template:\n' + bytes.hex(inputTemplate) + '\n')
            print('Hash retrieved from blockchain:\n' + blockchainHash.hex() + '\n')
            print('Hash retrieved by hashing data obtained from database:\n' + databaseHash.hexdigest() + '\n')
            print('Template obtained from database:\n' + bytes.hex(template) + '\n')
print()