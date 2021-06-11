#Idan Givati, 315902239, Matan Saloniko, 318570769
from typing import List
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

#A class to represent a merkle tree node.
class MerkleNode:
    def __init__(self, value):
        self.left = None
        self.right = None
        self.father = None
        self.value = hashlib.sha256(value.encode("UTF-8")).hexdigest()

#Returns the tree root.
def getRoot(node):
    while node.father != None:
        node = node.father
    return node

#Adds a leaf to the tree.
def addLeaf(leafs: List, plainText):
    leafs.append(MerkleNode(plainText))

#Uses the leafs to calculate the tree root.
def calcRoot(leafs: List):
    #If no leafs
    if len(leafs) == 0:
        return None
    #If only 1 leaf
    if len(leafs) == 1:
        return leafs[0]
    parents = leafs
    temp = []
    #Calculating each level of the tree.
    while len(parents) > 1:
        #Going over the nodes in the level.
        for i in range(0, len(parents), 2):
            flag = False
            joined = parents[i].value
            #Calculating the hash of both nodes.
            if i + 1 < len(parents):
                flag = True
                joined += parents[i + 1].value
            #Creating a father.
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
    #Returning the root.
    return parents[0]
        
#Creating proof of inclusion.
def createPOI(leafs, strNum):
    leafNum = int(strNum)
    if leafNum >= len(leafs):
        return
    #Calculating the tree root.
    root = calcRoot(leafs)
    #Getting the desired leaf.
    node = leafs[leafNum]
    result = ""
    #Checking if it has a brother from right or left.
    if leafNum % 2 == 1:
        result += "0" + node.father.left.value + " "
    else:
        if leafNum + 1 < len(leafs):
            result += "1" + node.father.right.value + " "
    #Going over every level and adding the brother.
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

#Checking and verifying proof of inclusion.    
def checkPOI(leafValue, inputData):
    #Calculating the hash of the input.
    hashedValue = hashlib.sha256(leafValue.encode("UTF-8")).hexdigest()
    if len(inputData) < 3:
        #print("False")     // according to the instruction we not suppose to print anything if the input isnt correct.
        return
    #Getting the tree root from the input POI.
    root = inputData[2]
    #Going over the POI and calculating the hashes
    for i in range(3, len(inputData)):
        currentString = inputData[i]
        if currentString[0] == '0':
            currentString = currentString[1:]
            currentHash = currentString + hashedValue
        else:
            currentString = currentString[1:]
            currentHash = hashedValue + currentString
        hashedValue = hashlib.sha256(currentHash.encode("UTF-8")).hexdigest()
    #Checking if the result hash is the same as the tree root.
    if root == hashedValue:
        print("True")
    else:
        print("False")


#Creating and printing RSA keys.
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


#Signing the current tree root with the input RSA key.
def signRoot(key, root):
    #Creating the private key from the input.
    privateKey = serialization.load_pem_private_key(
        key.encode(),
        password=None,
        backend=default_backend()
    )

    #Signing the root.
    signature = privateKey.sign(
        root.value.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    print(base64.b64encode(signature).decode("utf-8"))
    

#Checking the signature using the key provided and checking the decrypted message.
def confirmSignature(key, signature, text):
    #Creating the key from input.
    public_key = serialization.load_pem_public_key(
            key.encode(),
            backend=default_backend()
        )
    
    try:
        #Verifying the signature.
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

# Turning a received leaf value to 1.
def markLeaf(sparseLeaves, leafString):
    leafNum = int(leafString, 16)
    sparseLeaves.append(leafNum)
    sparseLeaves.sort()

# Calculating the root of the sparse tree
def calcSparseRoot(sparseLeaves):
    #In case we did not change the original (only 0) sparse merkle tree.
    if(len(sparseLeaves) < 1):
        return defaultCalc(256)
    return calcChangedSparse(sparseLeaves, 256, 255, "")


def calcChangedSparse(sparseLeaves, highLevel, currentLevel, result):
    position = 0
    flagHigh = False
    flagLow = False
    # If we reached our leaves.
    if(currentLevel == 0):
        # If the leaf we working on is even.
        if(sparseLeaves[0] % 2 == 0):
            # Checking if we have both leaves that has a value of 1.
            if len(sparseLeaves) > 1:
                result = hashlib.sha256(("1" + "1").encode("UTF-8")).hexdigest()
            else:
                result = hashlib.sha256(("1" + "0").encode("UTF-8")).hexdigest()
        else:
            result = hashlib.sha256(("0" + "1").encode("UTF-8")).hexdigest()
        return result

    for i in range(0, len(sparseLeaves)):
        # We want to check if one of our array numbers is bigger than half of the number of leaves.
        if(flagHigh == False):
            if((2**highLevel - sparseLeaves[i]) < (2 ** currentLevel)):
                flagHigh = True
                position = i
        if((2**highLevel - sparseLeaves[i]) > (2 ** currentLevel)):
            flagLow = True
    # If we dont have any number in our current array, that is bigger or lower than half of the current leaves, we will do a default calculation.
    if(flagHigh == True):
        result = result + calcChangedSparse(sparseLeaves[position:], highLevel, currentLevel - 1, result)
    if(flagLow == True):
        result = calcChangedSparse(sparseLeaves[0:position + 1], highLevel - 1, currentLevel - 1, result) + result
    if (flagHigh == False):
        result = result + defaultCalc(currentLevel)
    if (flagLow == False):
        result = defaultCalc(currentLevel) + result
    result = hashlib.sha256((result).encode("UTF-8")).hexdigest()
    return result
    
    
def defaultCalc(height):
    if(height == 0):
        return "0"
    result = defaultCalc(height - 1)
    result = hashlib.sha256((result + result).encode("UTF-8")).hexdigest()
    return result


#Wrong input.
def wrongInput():
    print("Wrong input. please select a number between 1-11")

def main():
    leafs = []
    sparseLeaves = []
    while True:
        #Getting input.
        inputText = input()
        splitted = inputText.strip().split(' ')
        #Input 1 - adding a leaf.
        if (splitted[0] == "1"):
            addLeaf(leafs, splitted[1])
        #Input 2 - calculating tree root.
        elif (splitted[0] == "2"):
            root = calcRoot(leafs)
            if (root == None):
                print()
            else:
                print(root.value)
        #Input 3 - creating proof of inclusion.
        elif (splitted[0] == "3"):
            createPOI(leafs, splitted[1])
        #Input 4 - checking proof of inclusion.
        elif (splitted[0] == "4"):
            checkPOI(splitted[1], splitted)
        #Input 5 - creating RSA keys.
        elif (splitted[0] == "5"):
            createRSAKeys()
        #Input 6 - signing current tree root.
        elif (splitted[0] == "6"):
            longInput = inputText[2:] + "\n"
            shortInput = input()
            while shortInput != "":
                longInput += shortInput + "\n"
                shortInput = input()
            signRoot(longInput, calcRoot(leafs))
        #Input 7 - verifying signature.
        elif (splitted[0] == "7"):
            longInput = inputText[2:] + "\n"
            shortInput = input()
            while shortInput != "":
                longInput += shortInput + "\n"
                shortInput = input()
            signatureInput = input()
            signatureArray = signatureInput.split(" ")
            confirmSignature(longInput, signatureArray[0], signatureArray[1])
        #Input 8 - 
        elif (splitted[0] == "8"):
            markLeaf(sparseLeaves, splitted[1])
        #Input 9 - 
        elif (splitted[0] == "9"):
            rootHash = calcSparseRoot(sparseLeaves)
            print(rootHash)
        #Input 10 - 
        elif (splitted[0] == "10"):
            createSparsePOI()
        #Input 11 - 
        elif (splitted[0] == "11"):
            checkSparsePOI()
        #Wrong input
        else:
            wrongInput()
    return


if __name__ == "__main__":
    main()