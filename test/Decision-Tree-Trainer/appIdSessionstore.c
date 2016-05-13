#include <stdio.h>
#include <stdlib.h>
#include<stdint.h>
#include<time.h>
//#include "sort.c"

#define MAX_REQUESTS_FOR_DT 25
#define MAX_PAYLOAD_BYTES 10
#define MAX_TCP_OPTIONS 10

/*
	AVL Tree to access socketpair by sessid
*/
typedef struct AVLTree_Node
{  uint16_t data;
   struct AVLTree_Node *left,*right;
   uint16_t ht;
   struct node *head;
}AVLTree_Node;


  AVLTree_Node *insertion(AVLTree_Node *,uint16_t,struct node *head);
AVLTree_Node * deletion(AVLTree_Node *T,uint16_t x);
  void  preorder(AVLTree_Node *);
  void  inorder(AVLTree_Node *);
  uint16_t   height( AVLTree_Node *);
  AVLTree_Node *rotateright(AVLTree_Node *);
  AVLTree_Node *rotateleft(AVLTree_Node *);
  AVLTree_Node *RR(AVLTree_Node *);
  AVLTree_Node *LL(AVLTree_Node *);
  AVLTree_Node *LR(AVLTree_Node *);
  AVLTree_Node *RL(AVLTree_Node *);
  uint16_t BF(AVLTree_Node *);


/*  Insert sessid and socket pair in AVL Tree		*/
AVLTree_Node* insertion(AVLTree_Node *T,uint16_t x, struct node *head)
{
    if(T==NULL)
    {
        T=(AVLTree_Node*)malloc(sizeof(AVLTree_Node));
        T->data=x;
	T->head = head;
        T->left=NULL;
        T->right=NULL;
    }
    else
        if(x > T->data)                // insert in right subtree
        {
            T->right=insertion(T->right,x,head);
            if(BF(T)==-2)
                if(x>T->right->data)
                    T=RR(T);
                else
                    T=RL(T);
        }
        else
            if(x<T->data)
            {
                T->left=insertion(T->left,x,head);
                if(BF(T)==2)
                    if(x < T->left->data)
                        T=LL(T);
                    else
                        T=LR(T);
            }
            T->ht=height(T);
	    //root=T;
            return(T);
}


/* delete sessid from AVLTree	*/
AVLTree_Node * deletion(AVLTree_Node *T,uint16_t x)
{       AVLTree_Node *p;

	if(T==NULL)
    {
        return NULL;
    }
    else

        if(x > T->data)                // insert in right subtree
        {
            T->right=deletion(T->right,x);
            if(BF(T)==2)
                if(BF(T->left)>=0)
                    T=LL(T);
                else
                    T=LR(T);
        }
        else
            if(x<T->data)
                {
                    T->left=deletion(T->left,x);
                    if(BF(T)==-2)//Rebalance during windup
                        if(BF(T->right)<=0)
                            T=RR(T);
                        else
                            T=RL(T);
                }
            else
              {
                //data to be deleted is found
                  if(T->right !=NULL)
                  {  //delete its inorder succesor
                      p=T->right;
                      while(p->left != NULL)
                      p=p->left;

                      T->data=p->data;
		      T->head=p->head;
                      T->right=deletion(T->right,p->data);
                      if(BF(T)==2)//Rebalance during windup
                        if(BF(T->left)>=0)
                            T=LL(T);
                        else
                            T=LR(T);
                   }
                  else
                   return(T->left);

              }
    T->ht=height(T);

	return(T);
}

uint16_t height(AVLTree_Node *T)
{
    uint16_t lh,rh;
    if(T==NULL)
        return(0);
    if(T->left==NULL)
        lh=0;
    else
        lh=1+T->left->ht;
    if(T->right==NULL)
        rh=0;
    else
        rh=1+T->right->ht;
    if(lh>rh)
        return(lh);
    return(rh);
}

AVLTree_Node * rotateright(AVLTree_Node *x)
{
    AVLTree_Node *y;
    y=x->left;
    x->left=y->right;
    y->right=x;
    x->ht=height(x);
    y->ht=height(y);
    return(y);
}

AVLTree_Node * rotateleft(AVLTree_Node *x)
{
    AVLTree_Node *y;
    y=x->right;
    x->right=y->left;
    y->left=x;
    x->ht=height(x);
    y->ht=height(y);
    return(y);
}
AVLTree_Node * RR(AVLTree_Node *T)
{
    T=rotateleft(T);
    return(T);
}
AVLTree_Node * LL(AVLTree_Node *T)
{
    T=rotateright(T);
    return(T);
}
AVLTree_Node * LR(AVLTree_Node *T)
{
    T->left=rotateleft(T->left);
    T=rotateright(T);
    return(T);
}
AVLTree_Node * RL(AVLTree_Node *T)
{
    T->right=rotateright(T->right);
    T=rotateleft(T);
    return(T);
}
uint16_t BF(AVLTree_Node *T)
{
    uint16_t lh,rh;
    if(T==NULL)
    return(0);
    if(T->left==NULL)
        lh=0;
    else
        lh=1+T->left->ht;
    if(T->right==NULL)
        rh=0;
    else
        rh=1+T->right->ht;
    return(lh-rh);
}
void preorder(AVLTree_Node *T)
{
    if(T!=NULL)
    {
        preorder(T->left);
        preorder(T->right);
    }
}

/* Returns AVLTree Node with sessid = data */
AVLTree_Node* searchNode (AVLTree_Node *T,uint16_t data)
{

	if(T==NULL)
	{
		return NULL;
	}
	if(T->data==data)
	{
		return T;
	}
	if(T->data>data)
	{
		return searchNode(T->left,data);
	}

	if(T->data<data)
	{
		return searchNode(T->right,data);
	}


}

/* checks whether element is available in avltree or not */
uint16_t searchElement (AVLTree_Node *T,uint16_t data)
{
	AVLTree_Node *r = searchNode(T,data);

	if(r!=NULL)
	{
		return 1;
	}

	return 0;

}

/* if sessid= data is available in AVL tree return socketpair struct*/
struct node* searchHead (AVLTree_Node *T,uint16_t data)
{
	AVLTree_Node *r = searchNode(T,data);
	if(r!=NULL)
	{
		return r->head;
	}
	return NULL;

}


/*
	LRU Queue for maintaining sessid
*/


// A Queue Node (Queue is implemented using Doubly Linked List)
typedef struct QNode
{
	struct QNode *prev, *next;
	uint16_t pageNumber; // the page number stored in this QNode
} QNode;

// A Queue (A FIFO collection of Queue Nodes)
typedef struct Queue
{
	uint16_t count; // Number of filled frames
	uint16_t numberOfFrames; // total number of frames
	QNode *front, *rear;
} Queue;

// A hash (Collection of pointers to Queue Nodes)
typedef struct Hash
{
	uint16_t capacity; // how many sessions can be there
	QNode* *array; // an array of queue nodes
} Hash;

// A utility function to create a new Queue Node. The queue Node
// will store the given 'sessionNumber'
QNode* newQNode( uint16_t pageNumber )
{
	// Allocate memory and assign 'pageNumber'
	QNode* temp = (QNode *)malloc( sizeof( QNode ) );
	temp->pageNumber = pageNumber;

	// Initialize prev and next as NULL
	temp->prev = temp->next = NULL;

	return temp;
}

// A utility function to create an empty Queue.
// The queue can have at most 'numberOfFrames' nodes
Queue* createQueue( uint16_t numberOfFrames )
{
	Queue* queue = (Queue *)malloc( sizeof( Queue ) );

	// The queue is empty
	queue->count = 0;
	queue->front = queue->rear = NULL;

	// Number of frames that can be stored in memory
	queue->numberOfFrames = numberOfFrames;

	return queue;
}

// A utility function to create an empty Hash of given capacity
Hash* createHash( uint16_t capacity )
{
	// Allocate memory for hash
	Hash* hash = (Hash *) malloc( sizeof( Hash ) );
	hash->capacity = capacity;

	// Create an array of pointers for refering queue nodes
	hash->array = (QNode **) malloc( hash->capacity * sizeof( QNode* ) );

	// Initialize all hash entries as empty
	uint16_t i;
	for( i = 0; i < hash->capacity; ++i )
		hash->array[i] = NULL;

	return hash;
}

// A function to check if there is slot available in memory
uint16_t AreAllFramesFull( Queue* queue )
{
	return queue->count == queue->numberOfFrames;
}

// A utility function to check if queue is empty
uint16_t isQueueEmpty( Queue* queue )
{
	return queue->rear == NULL;
}

void displayQueue(QNode* q)
{
	if(q== NULL)
		return;
	printf("%u  ",q->pageNumber);
	displayQueue(q->next);

}

// A utility function to delete a frame from queue
uint16_t deQueue( Queue* queue )
{
 uint16_t n ;
	if( isQueueEmpty( queue ) )
		return  ;

	// If this is the only node in list, then change front
	if (queue->front == queue->rear)
		queue->front = NULL;

	// Change rear and remove the previous rear
	QNode* temp = queue->rear;
	queue->rear = queue->rear->prev;

	//printf("\n\n%u",
		n=(temp->pageNumber);

	if (queue->rear)
		queue->rear->next = NULL;

	free( temp );

	// decrement the number of full frames by 1
	queue->count--;

	return n;
}

// A function to add a page with given 'pageNumber' to both queue
// and hash
void Enqueue( Queue* queue, Hash* hash, uint16_t pageNumber )
{
	// If all frames are full, remove the page at the rear
	if ( AreAllFramesFull ( queue ) )
	{
		// remove page from hash
		hash->array[ queue->rear->pageNumber ] = NULL;
		deQueue( queue );
	}

	// Create a new node with given page number,
	// And add the new node to the front of queue
	QNode* temp = newQNode( pageNumber );
	temp->next = queue->front;

	// If queue is empty, change both front and rear pointers
	if ( isQueueEmpty( queue ) )
		queue->rear = queue->front = temp;
	else // Else change the front
	{
		queue->front->prev = temp;
		queue->front = temp;
	}

	// Add page entry to hash also
	hash->array[ pageNumber ] = temp;

	// increment number of full frames
	queue->count++;
}

// This function is called when a page with given 'pageNumber' is referenced
// from cache (or memory). There are two cases:
// 1. Frame is not there in memory, we bring it in memory and add to the front
// of queue
// 2. Frame is there in memory, we move the frame to front of queue
void ReferencePage( Queue* queue, Hash* hash, uint16_t pageNumber )
{
	QNode* reqPage = hash->array[ pageNumber ];

	// the page is not in cache, bring it
	if ( reqPage == NULL )
		Enqueue( queue, hash, pageNumber );

	// page is there and not at front, change pointer
	else if (reqPage != queue->front)
	{
		// Unlink rquested page from its current location
		// in queue.
		reqPage->prev->next = reqPage->next;
		if (reqPage->next)
		reqPage->next->prev = reqPage->prev;

		// If the requested page is rear, then change rear
		// as this node will be moved to front
		if (reqPage == queue->rear)
		{
		queue->rear = reqPage->prev;
		queue->rear->next = NULL;
		}

		// Put the requested page before current front
		reqPage->next = queue->front;
		reqPage->prev = NULL;

		// Change prev of current front
		reqPage->next->prev = reqPage;

		// Change front to the requested page
		queue->front = reqPage;
	}
}



/**----------------------creates linked list remembering position that require changes -------------

	Link list maintaining the values of currently free sessids which can be assigned to new sessions

*/


uint16_t dsess_id=0;
#define MAX 500

Queue* q=NULL;
Hash* h =NULL;



void refer(uint16_t sessid)
{
	ReferencePage(q,h,sessid);

}

struct snode
{
    uint16_t index;
    struct snode *next;

}*start=NULL;


void insert(uint16_t ind)
{
    struct snode *p=start,*new,*prev=NULL;
    new=(struct snode *)malloc(sizeof(struct snode));


    if(start==NULL)
    {
        start=new;
        new->index=ind;
        new->next=NULL;
        return;
    }
    else
    {
        while(p!=NULL )
        {
            if((p->index)>ind)
            break;
            else
            {
                prev=p;
                p=p->next;
            }
        }
        new->next=p;
        if(prev!=NULL)
        prev->next=new;
        else
        start=new;
        new->index=ind;


    }
    return;

}

void remove_front()
{
    struct snode *ptr=NULL;

    if(start==NULL)
    {
        return ;
    }
    else
    {
        ptr=start;
        start=start->next;
        free(ptr);
        return;
    }
}

void remove_end()
{
    struct snode *ptr=start,*prev=NULL;

    if(start==NULL)
    {
        return;
    }
    else if(start->next==NULL)
    {
        ptr=start;
        start=start->next;
       free(ptr);
        return;

    }
    else
    {
        while(ptr->next!=NULL)
        {
            prev=ptr;
            ptr=ptr->next;
        }
        prev->next=NULL;
        free(ptr);
        return;
    }
}

void print()
{
    struct snode *ptr=start;
    if(start==NULL)
    return;
    while(ptr->next!=NULL)
    {
        printf("nnindex is %u ",ptr->index);
        ptr=ptr->next;
    }
    printf("nnindex is %u ",ptr->index);
}

uint16_t get_index()
{
    if(start==NULL)
    return (-1);
    return (start->index);

}

uint16_t get_last_index()
{
    struct snode *ptr=start;

    if(start==NULL)
    return -1;

    while(ptr->next!=NULL)
    ptr=ptr->next;
    return ptr->index;

}

uint16_t getSessionId()
{
	uint16_t i;
	if(start==NULL)
	{
		if(!(isQueueEmpty(q)))
		{
			return deQueue(q);
		}
		else
		{
			if(dsess_id>=MAX)
			{
				dsess_id=0;
			}


			return dsess_id++;
		}
	}
	else
	{
		i=get_index();
		remove_front();
		return i;

	}
}


int isNull()
{
	if(start==NULL)
		return 1;

	return 0;
}

/*
	Hash table to store socketpair and session info
*/

struct hash *hashTable = NULL;
uint32_t eleCount ;

struct node
{
    uint32_t ip1, ip2;

    uint16_t p1, p2;
    uint16_t whichIsSource; //0 for ip1,p1 or 1 otherwise
    uint16_t reqPacket[MAX_REQUESTS_FOR_DT], resPacket[MAX_REQUESTS_FOR_DT];
    uint16_t reqPayload[MAX_REQUESTS_FOR_DT], resPayload[MAX_REQUESTS_FOR_DT];
    uint8_t reqPayloadBytes[MAX_REQUESTS_FOR_DT][MAX_PAYLOAD_BYTES], resPayloadBytes[MAX_REQUESTS_FOR_DT][MAX_PAYLOAD_BYTES];
    double reqPacketAvg, resPacketAvg;
    double reqPayloadAvg,resPayloadAvg;
    uint16_t reqCount, resCount;
	/*TCP_OPTIONS*/
   // uint8_t reqOptions[MAX_REQUESTS_FOR_DT][MAX_TCP_OPTIONS];
   // uint8_t resOptions[MAX_REQUESTS_FOR_DT][MAX_TCP_OPTIONS];
    uint64_t duration;
    uint16_t sessid,total_packets;
    uint32_t total_bytes;
    struct node *next;
};

struct hash
{
    struct node *head;
    uint32_t count;
};



uint32_t getIndex(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2)
{
	uint32_t x;      //MUrmurHash
	x= (ip1 + ip2 + p1 + p2);
	x= ((x >> 16) ^ x ) * 0x45d9f3b;
	x= ((x >> 16) ^ x ) * 0x45d9f3b;
	x= ((x >> 16) ^ x ) ;

	return (x % eleCount);
//	return 1;

}

uint32_t isSmaller(uint32_t a, uint32_t b)
{
	if (a < b)
		return 1;

	return 0;
	//a < b ? return 1 : return 0;
}



//print all hash to CSV for later training of DT
int appId = 1;
printForDT(struct node *s)

{
	int i,j;
	//int count = 0;
	FILE *fpDT = fopen("/usr/dt.txt","a");
	FILE *tfp = fopen("/usr/apps.txt","a");

	fprintf(fpDT,"%f, %f, ",s->reqPayloadAvg,s->resPayloadAvg);
	for(i=0;i<MAX_REQUESTS_FOR_DT;i++)
	{
		fprintf(fpDT,"%u, ",s->reqPayload[i]);
	}
	for(i=0;i<MAX_REQUESTS_FOR_DT;i++)
	{
		fprintf(fpDT,"%u, ",s->resPayload[i]);
	}

	fprintf(fpDT,"%f, %f, ",s->reqPacketAvg,s->resPacketAvg);				//count+=2;





	for(i=0;i<MAX_REQUESTS_FOR_DT;i++)
	{
		fprintf(fpDT,"%u, ",s->reqPacket[i]);
	}
	for(i=0;i<MAX_REQUESTS_FOR_DT;i++)
	{
		fprintf(fpDT,"%u, ",s->resPacket[i]);

	}
	fprintf(fpDT,"%u, ",s->duration);

	for(i=0;i<MAX_REQUESTS_FOR_DT;i++)
	{
		for(j=0;j<MAX_PAYLOAD_BYTES;j++)
		{
			fprintf(fpDT,"%u, ",s->reqPayloadBytes[i][j]);
		}
	}
	for(i=0;i<MAX_REQUESTS_FOR_DT;i++)
	{
		for(j=0;j<MAX_PAYLOAD_BYTES;j++)
		{
			fprintf(fpDT,"%u, ",s->resPayloadBytes[i][j]);
		}
	}
	/*TCP_OPTIONS*/
/*	for(i=0;i<MAX_REQUESTS_FOR_DT;i++)
	{
		for(j=0;j<MAX_TCP_OPTIONS;j++)
		{
			fprintf(fpDT,"%u, ",s->reqOptions[i][j]);			//count++;
		}
	}
	for(i=0;i<MAX_REQUESTS_FOR_DT-1;i++)
	{
		for(j=0;j<MAX_TCP_OPTIONS;j++) // 9 because print last without comma
		{
			fprintf(fpDT,"%u, ",s->resOptions[i][j]);			//count++;
		}
	}
	for(j=0;j<MAX_TCP_OPTIONS-1;j++)
	{
		fprintf(fpDT,"%u, ",s->resOptions[9][j]);					//count++;
	}
	fprintf(fpDT,"%u, ",s->resOptions[9][9]);						//count++;
*/

	//printf("HERE -_-");
	//printf("%d",count);
	//fprintf(fpDT,"app%d%d\n",time(NULL),appid);
	fprintf(fpDT,"app%d\n",appId);
	fprintf(tfp,"app%d, ",appId);
	appId++;
	fclose(fpDT);
	fclose(tfp);
}

/* find sessid by socketpair in hash */
uint16_t sessidInHash(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2)
{

	uint16_t sid;
	uint32_t swap_ip;
	uint16_t swap_port;

	if (!isSmaller(ip1, ip2))
	{
		swap_ip = ip1;
		ip1 = ip2;
		ip2 = swap_ip;

		swap_port = p1;
		p1 = p2;
		p2 = swap_port;
	}

    uint32_t hashIndex = getIndex(ip1, ip2, p1, p2), flag = 0;
    struct node *myNode=NULL;
    myNode = hashTable[hashIndex].head;
    if (!myNode) {
       // printf("Search element unavailable in hash table\n");
        sid=0;
	return sid;
    }
    while (myNode != NULL) {
		if (myNode->ip1 == ip1 && myNode->ip2 == ip2 &&
			myNode->p1 == p1 && myNode->p2 == p2)
		{
            flag = 1;
	    sid= myNode->sessid;

            break;
        }
        myNode = myNode->next;
    }
	if (!flag)
	{
		sid=0;
		return sid;
	}
    return sid;
}


/* add cumulative info to existing record */
void addCumulativeInfo(uint32_t ip1 , uint32_t ip2 , uint16_t p1 , uint16_t p2, uint32_t payload_size)
{

    uint32_t hashIndex = getIndex(ip1, ip2, p1, p2), flag = 0;
    struct node *myNode=NULL;
    myNode = hashTable[hashIndex].head;

	myNode->total_bytes += payload_size;
	myNode->total_packets += 1;

}

/*check if packet is request or response in session*/
int isRequest(uint32_t ip1, uint16_t p1, struct node *node)
{
	if((node->whichIsSource == 0) && (ip1==node->ip1) && (p1==node->p1))
	{
		return 1;
	}
	else if((node->whichIsSource == 1) && (ip1==node->ip2) && (p1=node->p2))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

/* checks if socket pairs are avl in hash */
struct node * searchInHash(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2)
{


	uint32_t swap_ip;
	uint16_t swap_port;

	if (!isSmaller(ip1, ip2))
	{
		swap_ip = ip1;
		ip1 = ip2;
		ip2 = swap_ip;

		swap_port = p1;
		p1 = p2;
		p2 = swap_port;
	}

    uint32_t hashIndex = getIndex(ip1, ip2, p1, p2), flag = 0;
    struct node *myNode=NULL;
    myNode = hashTable[hashIndex].head;
    if (!myNode)
    {
       // printf("Search element unavailable in hash table\n");
        return NULL;
    }
    while (myNode != NULL) {
		if (myNode->ip1 == ip1 && myNode->ip2 == ip2 &&
			myNode->p1 == p1 && myNode->p2 == p2)
		{
		    flag = 1;
		    break;
        	}
        myNode = myNode->next;
    }
	if (!flag)
	{
		return NULL;
	}
    return myNode;
}




void deleteFromHash(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2)
{
	uint32_t swap_ip;
	uint16_t swap_port;

	if (!isSmaller(ip1, ip2))
	{
		swap_ip = ip1;
		ip1 = ip2;
		ip2 = swap_ip;

		swap_port = p1;
		p1 = p2;
		p2 = swap_port;
	}



    /* find the bucket using hash index*/
    uint32_t hashIndex = getIndex(ip1, ip2, p1, p2), flag = 0;
    struct node *temp, *myNode;
    /* get the list head from current bucket*/
    myNode = hashTable[hashIndex].head;
    if (!myNode)
	{
   //     printf("Given data is not present in hash Table!!\n");
        return;
    }
   temp = myNode;
    while (myNode != NULL) {
        /* delete the node with given key */
        if (myNode->ip1 == ip1 && myNode->ip2 == ip2 &&
			myNode->p1 == p1 && myNode->p2 == p2)
		{

            flag = 1;
            if (myNode == hashTable[hashIndex].head)
                hashTable[hashIndex].head = myNode->next;
            else
                temp->next = myNode->next;

            hashTable[hashIndex].count--;

//		deletion(myNode->sessid);
            free(myNode);
            break;
        }
       temp = myNode;

        myNode = myNode->next;
    }
 //   if (flag)
   //     printf("\nData deleted successfully from Hash Table\n");
    //else
      //  printf("\nGiven data is not present in hash Table!!!!\n");
//		deletion(myNode->sess;
   return;
}

void deleteFromHashbySessId(uint16_t sessid, AVLTree_Node *root)
{

	struct node *temp ;
    temp = (struct node *)searchHead(root,sessid);
	deleteFromHash(temp->ip1,temp->ip2,temp->p1,temp->p2);
}

void display()
{
    struct node *myNode;
    uint32_t i;
    for (i = 0; i < eleCount; i++) {
        if (hashTable[i].count == 0)
            continue;
        myNode = hashTable[i].head;
        if (!myNode)
            continue;
        printf("\nData at index %u in Hash Table:\n", i);
        printf("ip1     p1          ip2           p2           sessid           packet_count            which\n");
        printf("------------------------------------------------------------------------------------------------------------------\n");
        while (myNode != NULL) {
            printf("%u             ", myNode->ip1);
            printf("%u             ", myNode->p1);
            printf("%u             ", myNode->ip2);
            printf("%u             ", myNode->p2);
            printf("%u             ", myNode->sessid);
            printf("%u             ", myNode->total_packets);
	    printf("%u            \n", myNode->whichIsSource);

            myNode = myNode->next;
        }
    }
    return;
}

void displayNode(struct node *myNode)
{

        if (!myNode)
            return;
            printf("%u             ", myNode->ip1);
            printf("%u             ", myNode->p1);
            printf("%u             ", myNode->ip2);
            printf("%u             ", myNode->p2);
            printf("%u             ", myNode->sessid);
          //  printf("%u             ", myNode->payload);
	  //  printf("%u             \n", myNode->total_packets);
}
void initializeHash(uint16_t n)
{
	if(hashTable==NULL)
	{
    		hashTable = (struct hash *) calloc(n, sizeof(struct hash));
	}
	eleCount=n;
	q= createQueue(n);
	h=createHash(n);
}

void inorder(AVLTree_Node *T)
{
	if(T!=NULL)
    {
        inorder(T->left);
        printf("\n %u ",T->data);
        displayNode(T->head);
        inorder(T->right);
    }
}
