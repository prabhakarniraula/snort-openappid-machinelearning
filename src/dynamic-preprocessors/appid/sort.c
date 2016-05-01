#include <stdio.h>
#include<stdint.h>
//#include<time.h>

void sort(TCPOptions array[],int size)
{
	//int n = sizeof(array) / sizeof(int),
 
	int c, d;
	TCPOptions t;
	//printf("%d\n", n);
	for (c = 1; c <= size - 1; c++) 
	{
		d = c;

		while (d > 0 && array[d].option_code < array[d - 1].option_code) 
		{
			t = array[d];
			array[d] = array[d - 1];
			array[d - 1] = t;

			d--;
		}
	}
}

int contains(TCPOptions array[], uint8_t element, int size)
{
	int i=0;
	for(i=0;i<size;i++)
	{
		if(array[i].option_code == element)
		{
			return i;
		}
	}	
	return -1;
}

/*int main()
{
  int n, array[15], c, d, t;
  srand(time(NULL));
  int i = 0;
  for (int i = 0; i < 5; i++)
  {
	  array[i] = rand();
  }
  n = sizeof(array) / sizeof(int);
  //printf("\n %d integers\n", n);
 
 
  sort(array,n);
 
  printf("Sorted list in ascending order:\n");
 
  for (c = 0; c <= n - 1; c++) {
    printf("%d\n", array[c]);
  }
  getch();
  return 0;
}*/
