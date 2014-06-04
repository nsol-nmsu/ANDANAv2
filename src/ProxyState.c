#include "ProxyState.h"
#include "Util.h"

/**
 * TODO
 */ 
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
		while (curr->next != NULL)
		{
			curr = curr->next;
		}
		curr->next = entry;
	}
	entry->next = NULL; // terminate the list
}

/**
 * TODO
 */ 
ProxySessionTableEntry* AllocateNewSessionEntry(ProxySessionTable* table)
{
	ProxySessionTableEntry* newEntry = (ProxySessionTableEntry*)malloc(sizeof(ProxySessionTableEntry));
	ProxySessionTableEntry* curr = table->head;
	DEBUG_PRINT("curr = %p\n", curr);
	if (curr == NULL)
	{
		DEBUG_PRINT("AllocateNewSessionEntry: Inserting new entry into the table\n");
		table->head = newEntry;
		return newEntry;
	}
	else
	{
		DEBUG_PRINT("AllocateNewSessionEntry: Appending to the end of the table\n");
		while (curr->next != NULL)
		{
			curr = curr->next;
		}
		DEBUG_PRINT("Setting next\n");
		curr->next = (ProxySessionTableEntry*)malloc(sizeof(ProxySessionTableEntry));
		memcpy(curr->next, newEntry, sizeof(ProxySessionTable));
		DEBUG_PRINT("Fixing entry\n");
	}
	newEntry->next = NULL; // terminate the list
	return newEntry;
}

/**
 * TODO
 */ 
ProxySessionTableEntry* FindEntryByIndex(ProxySessionTable* table, uint8_t* index, uint32_t len)
{
	ProxySessionTableEntry* curr = table->head;
	DEBUG_PRINT("curr = %p\n", curr);
	while (curr != NULL)
	{
		print_hex(index, len);
		printf("\n");
		print_hex(curr->session_index, len);
		printf("\ndone\n");
		if (memcmp(curr->session_index, index, len) == 0)
		{
			return curr;
		}
		curr = curr->next;
	}	
	return NULL;	
}

/**
 * TODO
 */ 
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
		while (curr->next != NULL)
		{
			curr = curr->next;
		}
		curr->next = (ProxyStateTableEntry*)malloc(sizeof(ProxyStateTableEntry));
		memcpy(curr->next, entry, sizeof(ProxyStateTableEntry));
	}
	entry->next = NULL; // terminate the list
}

/**
 * TODO
 */ 
ProxyStateTableEntry* AllocateNewStateEntry(ProxyStateTable* table)
{
	ProxyStateTableEntry* newEntry = (ProxyStateTableEntry*)malloc(sizeof(ProxyStateTableEntry));
	ProxyStateTableEntry* curr = table->head;
	if (curr == NULL)
	{
		DEBUG_PRINT("Inserting new entry into the table\n");
		table->head = newEntry;
		return newEntry;
	}
	else
	{
		DEBUG_PRINT("Appending to the end of the table\n");
		while (curr->next != NULL)
		{
			curr = curr->next;
		}
		curr->next = (ProxyStateTableEntry*)malloc(sizeof(ProxyStateTableEntry));
		memcpy(curr->next, newEntry, sizeof(ProxyStateTableEntry));
	}
	newEntry->next = NULL; // terminate the list
	return newEntry;
}

/**
 * TODO
 */ 
ProxyStateTableEntry* FindStateEntry(ProxyStateTable* table, uint8_t* key, uint32_t len)
{
	ProxyStateTableEntry* curr = table->head;
	while (curr != NULL)
	{
		if (curr->inklen == len && memcmp(curr->ink, key, len) == 0)
		{
			return curr;
		}
		curr = curr->next;
	}	
	return NULL;	
}

/**
 * TODO
 */ 
void AddUpstreamStateEntry(UpstreamProxyStateTable* table, UpstreamProxyStateTableEntry* entry)
{
	UpstreamProxyStateTableEntry* curr = table->head;
	if (curr == NULL)
	{
		DEBUG_PRINT("Inserting new entry into the table\n");
		table->head = entry;
	}
	else
	{
		DEBUG_PRINT("Appending to the end of the table\n");
		while (curr->next != NULL)
		{
			curr = curr->next;
		}
		curr->next = (UpstreamProxyStateTableEntry*)malloc(sizeof(UpstreamProxyStateTableEntry));
		memcpy(curr->next, entry, sizeof(UpstreamProxyStateTableEntry));
	}
	entry->next = NULL; // terminate the list
}

/**
 * TODO
 */
UpstreamProxyStateTableEntry* AllocateNewUpstreamStateEntry(UpstreamProxyStateTable* table)
{
	UpstreamProxyStateTableEntry* newEntry = (UpstreamProxyStateTableEntry*)malloc(sizeof(UpstreamProxyStateTableEntry));
	UpstreamProxyStateTableEntry* curr = table->head;
	DEBUG_PRINT("curr = %p\n", curr);
	if (curr == NULL)
	{
		DEBUG_PRINT("AllocateNewUpstreamStateEntry: Inserting new entry into the table\n");
		table->head = newEntry;
		return newEntry;
	}
	else
	{
		DEBUG_PRINT("AllocateNewUpstreamStateEntry: Appending to the end of the table\n");
		while (curr->next != NULL)
		{
			curr = curr->next;
		}
		DEBUG_PRINT("Setting next\n");
		curr->next = (UpstreamProxyStateTableEntry*)malloc(sizeof(UpstreamProxyStateTableEntry));
		memcpy(curr->next, newEntry, sizeof(UpstreamProxyStateTableEntry));
		DEBUG_PRINT("Fixing entry\n");
	}
	newEntry->next = NULL; // terminate the list
	return newEntry;
}

/**
 * TODO
 */
UpstreamProxyStateTableEntry* FindUpstreamStateEntry(UpstreamProxyStateTable* table, uint8_t* interestName, uint32_t len)
{
	UpstreamProxyStateTableEntry* curr = table->head;
	while (curr != NULL)
	{
		if (curr->inklen == len && memcmp(curr->ink, interestName, len) == 0)
		{
			return curr;
		}
		curr = curr->next;
	}	
	return NULL;	
}
