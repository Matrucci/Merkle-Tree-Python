
from typing import List
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

class MerkleNode:
    def __init__(self, value):
        self.left = None
        self.right = None
        self.father = None
        self.value = hashlib.sha256(value.encode("UTF-8")).hexdigest()


def getRoot(node):
    while node.father != None:
        node = node.father
    return node

def addLeaf(leafs: List, plainText):
    leafs.append(MerkleNode(plainText))

'''
def calcRoot(leafs: List):
    #In case we already calculated the root of the tree.
    if leafs[len(leafs) - 1].father != None:
        root = leafs[len(leafs) - 1]
        while root.father != None:
            root = root.father
        print(root.value)
        return
    #No leafs.
    if len(leafs) == 0:
        return
    #There's just one leaf.
    if len(leafs) == 1:
        print(leafs[0].value)
        return
    #In case we need to calculate it.
    for i in range(0, len(leafs), 2):
        if (leafs[i].father == None or (i + 1 < len(leafs) and leafs[i + 1].father == None)): 
            flag = False
            joined = leafs[i].value
            if i + 1 < len(leafs):
                flag = True
                joined = joined + leafs[i + 1].value
            leafs[i].father = MerkleNode(joined)
            leafs[i].father.left = leafs[i]
            if flag:
                leafs[i + 1].father = leafs[i].father
                leafs[i + 1].father.right = leafs[i + 1]
'''

def calcRoot(leafs: List):
    if len(leafs) == 0:
        return None
    if len(leafs) == 1:
        return leafs[0]
    parents = leafs
    temp = []
    while len(parents) > 1:
        for i in range(0, len(parents), 2):
            flag = False
            joined = parents[i].value
            if i + 1 < len(parents):
                flag = True
                joined += parents[i + 1].value
            if flag == True:
                node = MerkleNode(joined)
                parents[i].father = node
                parents[i + 1].father = node
                node.left = parents[i]
                node.right = parents[i + 1]
                temp.append(node)
            else:
                newNode = MerkleNode("")
                newNode.value = parents[i].value
                newNode.left = parents[i]
                parents[i].father = newNode
                temp.append(newNode)
        parents = temp
        temp = []
        #print("THE LENGTH IS: " + str(len(parents)))
    return parents[0]
        

def createPOI(leafs, strNum):
    leafNum = int(strNum)
    if leafNum >= len(leafs):
        return
        #return error
    root = calcRoot(leafs)
    node = leafs[leafNum]
    result = ""
    if leafNum % 2 == 1:
        result += "0" + node.father.left.value + " "
        #result += node.value + " "
    else:
        #result += node.value + " "
        if leafNum + 1 < len(leafs):
            result += "1" + node.father.right.value + " "
    while node.father.value != root.value:
        node = node.father
        if node == node.father.left:
            if node.father.right != None:
                result += "1" + node.father.right.value + " "
        elif node == node.father.right:
            if node.father.left != None:
                result = "0" + node.father.left.value + " " + result
    result = root.value + " " + result
    result.strip()
    print(result)
        
def checkPOI(leafValue, inputData):
    hashedValue = hashlib.sha256(leafValue.encode("UTF-8")).hexdigest()
    if len(inputData) < 3:
        print(False)
        return
    root = inputData[2]
    for i in range(3, len(inputData)):
        currentString = inputData[i]
        if currentString[0] == '0':
            currentString = currentString[1:]
            currentHash = currentString + hashedValue
        else:
            currentString = currentString[1:]
            currentHash = hashedValue + currentString
        hashedValue = hashlib.sha256(currentHash.encode("UTF-8")).hexdigest()
    if root == hashedValue:
        print("True")
    else:
        print("False")

        
def createRSAKeys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    print(pem.decode("UTF-8"))

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print(pem.decode("UTF-8"))

def signRoot(key, root):
    privateKey = serialization.load_pem_private_key(
        key.encode(),
        password=None,
        backend=default_backend()
    )

    signature = privateKey.sign(
        root.value.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    print(base64.b64encode(signature).decode("utf-8"))

    #signature_encode = signature.decode("UTF-8")
    #signature_base64 = base64.b64encode(signature_encode)
    #print(signature_base64)
    

def confirmSignature(key, signature, text):
    public_key = serialization.load_pem_public_key(
            key.encode(),
            backend=default_backend()
        )
    
    try:
        public_key.verify(
        base64.decodebytes(signature.encode()),
        text.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )
        
        print("True")
    except:
        print("False")


def main():
    leafs = []
    while True:
        inputText = input()
        splitted = inputText.strip().split(' ')
        if (splitted[0] == "1"):
            addLeaf(leafs, splitted[1])
        elif (splitted[0] == "2"):
            root = calcRoot(leafs)
            if (root == None):
                print()
            else:
                print(root.value)
        elif (splitted[0] == "3"):
            createPOI(leafs, splitted[1])
        elif (splitted[0] == "4"):
            checkPOI(splitted[1], splitted)
        elif (splitted[0] == "5"):
            createRSAKeys()
        elif (splitted[0] == "6"):
            longInput = inputText[2:] + "\n"
            shortInput = input()
            while shortInput != "":
                longInput += shortInput + "\n"
                shortInput = input()
            signRoot(longInput, calcRoot(leafs))
        elif (splitted[0] == "7"):
            longInput = inputText[2:] + "\n"
            shortInput = input()
            while shortInput != "":
                longInput += shortInput + "\n"
                shortInput = input()
            signatureInput = input()
            signatureArray = signatureInput.split(" ")
            confirmSignature(longInput, signatureArray[0], signatureArray[1])
        elif (splitted[0] == "8"):
            markLeaf()
        elif (splitted[0] == "9"):
            calcSparseRoot()
        elif (splitted[0] == "10"):
            createSparsePOI()
        elif (splitted[0] == "11"):
            checkSparsePOI()
        else:
            wrongInput()
    return


if __name__ == "__main__":
    main()