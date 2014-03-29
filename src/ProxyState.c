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