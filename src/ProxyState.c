#include "ProxyState.h"
#include "Util.h"

void AppendSessionEntry(ProxySessionTable* table, ProxySessionTableEntry* entry)
{
	ProxySessionTableEntry* curr = table->head;
	if (curr == NULL)
	{
		DEBUG_PRINT("Inserting new entry into the table\n");
		table->head = entry;
	}
	else
	{
		DEBUG_PRINT("Appending to the end of the table\n");
		while (curr != NULL)
		{
			curr = curr->next;
		}
		curr->next = entry;
	}
	entry->next = NULL; // terminate the list
}

ProxySessionTableEntry* AllocateNewSessionEntry(ProxySessionTable* table)
{
	ProxySessionTableEntry* newEntry = (ProxySessionTableEntry*)malloc(sizeof(ProxySessionTableEntry));
	ProxySessionTableEntry* curr;
	if (curr == NULL)
	{
		DEBUG_PRINT("Inserting new entry into the table\n");
		table->head = newEntry;
		return newEntry;
	}
	else
	{
		DEBUG_PRINT("Appending to the end of the table\n");
		while (curr != NULL)
		{
			curr = curr->next;
		}
		curr->next = newEntry;
	}
	newEntry->next = NULL; // terminate the list
	return newEntry;
}

ProxySessionTableEntry* FindEntryByIndex(ProxySessionTable* table, uint8_t* index, int len)
{
	ProxySessionTableEntry* curr = table->head;
	while (curr != NULL)
	{
		if (memcmp(curr->session_index, index, len) == 0)
		{
			return curr;
		}
	}	
	return NULL;	
}

void AddStateEntry(ProxyStateTable* table, ProxyStateTableEntry* entry)
{
	ProxyStateTableEntry* curr = table->head;
	if (curr == NULL)
	{
		DEBUG_PRINT("Inserting new entry into the table\n");
		table->head = entry;
	}
	else
	{
		DEBUG_PRINT("Appending to the end of the table\n");
		while (curr != NULL)
		{
			curr = curr->next;
		}
		curr->next = entry;
	}
	entry->next = NULL; // terminate the list
}