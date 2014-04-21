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
		while (curr != NULL)
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

/**
 * TODO
 */ 
ProxySessionTableEntry* FindEntryByIndex(ProxySessionTable* table, uint8_t* index, uint32_t len)
{
	ProxySessionTableEntry* curr = table->head;
	while (curr != NULL)
	{
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
		curr->next = entry;
	}
	entry->next = NULL; // terminate the list
}

/**
 * TODO
 */ 
ProxyStateTableEntry* AllocateNewStateEntry(ProxyStateTable* table)
{
	ProxyStateTableEntry* newEntry = (ProxyStateTableEntry*)malloc(sizeof(ProxyStateTableEntry));
	ProxyStateTableEntry* curr;
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
		curr->next = newEntry;
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
		curr->next = entry;
	}
	entry->next = NULL; // terminate the list
}

/**
 * TODO
 */
UpstreamProxyStateTableEntry* AllocateNewUpstreamStateEntry(UpstreamProxyStateTable* table)
{
	UpstreamProxyStateTableEntry* newEntry = (UpstreamProxyStateTableEntry*)malloc(sizeof(UpstreamProxyStateTableEntry));
	UpstreamProxyStateTableEntry* curr;
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
		curr->next = newEntry;
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
