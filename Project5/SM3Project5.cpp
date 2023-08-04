#include<iostream>
#include<iomanip>
#include<string>
#include<vector>
#include <time.h>　　　
#include"sha256.h"
using namespace std;

struct Node {
    std::string hash;
    Node* left;
    Node* right;
    Node(string data)
    {
        this->hash = data;
    }
};

struct MerkleTree {
    Node* root;
    MerkleTree(vector<Node*> blk);
    ~MerkleTree();
    void dlt(Node* n);
};


string sha256(string str) {
    Sha256 hash0;
    string hash_str = hash0.getHexMessageDigest(str);
    return hash_str;
}



MerkleTree::MerkleTree(vector<Node*> blk)
{
    vector<Node*> nodes;
    while (blk.size() != 1) {
        for (unsigned int l = 0, n = 0; l < blk.size(); l = l + 2, n++) {
            if (l != blk.size() - 1) {
                nodes.push_back(new Node(sha256(blk[l]->hash + blk[l + 1]->hash)));
                nodes[n]->left = blk[l];
                nodes[n]->right = blk[l + 1];
            }
            else {
                nodes.push_back(blk[l]);
            }
        }
        blk = nodes;
        nodes.clear();

    }
    this->root = blk[0];
}

MerkleTree::~MerkleTree()
{

    dlt(root);
}

void MerkleTree::dlt(Node* n)
{
    if (n) {
        dlt(n->left);
        dlt(n->right);
        n = NULL;
        delete n;
    }
}



int main() {
    vector<Node*> leaves;
    clock_t start, end;
    start = clock();
    for (int i = 0; i < 10; i++)
    {
        leaves.push_back(new Node(sha256("1")));
        leaves[i]->left = NULL;
        leaves[i]->right = NULL;
    }
    MerkleTree* hashTree = new MerkleTree(leaves);
    end = clock();

    cout << hashTree->root->hash<<endl;
    cout << "time = " << double(end - start) / CLOCKS_PER_SEC << "s" << endl;
    return 0;
}
