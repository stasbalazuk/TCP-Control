typedef struct _ProcessList
{
	PVOID NextItem;
	PVOID pEPROCESS;
} TProcessList, *PProcessList;


BOOLEAN IsAdded(PProcessList List, PVOID pEPROCESS)
{
	PProcessList Item = List;
	while (Item)
	{
		if (pEPROCESS == Item->pEPROCESS) return TRUE;
		Item = Item->NextItem;
	}
	return FALSE;
}

void DelItem(PProcessList *List, PVOID pEPROCESS)
{
	PProcessList Item = *List;
	PProcessList Prev = NULL;
	while (Item)
	{
	    if (pEPROCESS == Item->pEPROCESS)
		{
	    	if (Prev) Prev->NextItem = Item->NextItem; else *List = Item->NextItem;
			ExFreePool(Item);
			return;
		}
		Prev = Item;
		Item = Item->NextItem;
	}
	return;
}


void FreePointers(PProcessList List)
{
    PProcessList Item = List;
	PVOID Mem;
	while (Item)
	{
		Mem = Item;	
		Item = Item->NextItem;
		ExFreePool(Mem);
	}
	return;
}


void AddItem(PProcessList *List, PVOID pEPROCESS)
{
	PProcessList wNewItem;
	wNewItem = ExAllocatePool(NonPagedPool, sizeof(TProcessList));
	wNewItem->NextItem = *List;
	*List = wNewItem;
	wNewItem->pEPROCESS = pEPROCESS;
	return;
}