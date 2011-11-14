// HookDll.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "HookDll.h"
#include "Dbghelp.h"
#include "ConfigDlg.h"
#include "ModuleInfo.h"
#include "HookFunctions.h"
#include "..\Common\Common.h"
#include "ArrayEx.h"
//#include <afxtempl.h>
#include <afxmt.h>
#include <new.h>

//#ifdef _DEBUG
//#define new DEBUG_NEW
//#undef THIS_FILE
//static char THIS_FILE[] = __FILE__;
//#endif

BEGIN_MESSAGE_MAP(CHookDllApp, CWinApp)
    //{{AFX_MSG_MAP(CHookDllApp)
        // NOTE - the ClassWizard will add and remove mapping macros here.
        //    DO NOT EDIT what you see in these blocks of generated code!
    //}}AFX_MSG_MAP
END_MESSAGE_MAP()


//#define ENABLE_LOG
/////////////////////////////////////////////////////////////////////////////
// CHookDllApp construction


//////////////////////////////////////////////////////////////////////////////////




CHookDllApp::CHookDllApp()
{
}


#define STACKWALK_MAX_NAMELEN 1024
CHookDllApp theApp;

typedef CArrayEx<DWORD64,DWORD64> STACK_ARRAY;
struct MEM_INFO
{
    STACK_ARRAY *parCallStack;
    SIZE_T nMemSize;
};

CMapEx<LPVOID,LPVOID,MEM_INFO,MEM_INFO> m_MemMap;
bool g_bTrack = true;
bool g_bHooked = false;
HOOK_TYPE_e g_HookType = HT_UNKNOWN;
int g_StackDepth = 20;
CCriticalSection SyncObj;


CONTEXT g_stContext = {0};

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) 
{
    g_stContext = *(ep->ContextRecord);
    return EXCEPTION_EXECUTE_HANDLER;
}

void GetContext()
{
    __try
        {
            int n = 0;
            throw n;
        }
        __except(filter( GetExceptionCode(), GetExceptionInformation()))
        {
        }
}

#ifdef _M_IX86
void StackDump( LPVOID pMem, DWORD dwBytes)
{
        STACKFRAME64 stStackFrame = {0};
        CONTEXT stContext = {0};
        stContext.ContextFlags = CONTEXT_ALL;    
        __asm    call x
        __asm x: pop eax
        __asm    mov stContext.Eip, eax
        __asm    mov stContext.Ebp, ebp
        __asm    mov stContext.Esp, esp

        stStackFrame.AddrPC.Offset = stContext.Eip;
        stStackFrame.AddrPC.Mode = AddrModeFlat;
        stStackFrame.AddrFrame.Offset = stContext.Ebp;
        stStackFrame.AddrFrame.Mode = AddrModeFlat;
        stStackFrame.AddrStack.Offset = stContext.Esp;
        stStackFrame.AddrStack.Mode = AddrModeFlat;
 
//         BYTE SymBol[ sizeof(SYMBOL_INFO) + STACKWALK_MAX_NAMELEN ] = {0};
// 
//         SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)SymBol;
//         pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
//         pSymbol->MaxNameLen = STACKWALK_MAX_NAMELEN;
// 
//         IMAGEHLP_LINE64 Line = {0};
//         Line.SizeOfStruct = sizeof( IMAGEHLP_LINE64 );
        
        HANDLE hProcess = GetCurrentProcess();
        MEM_INFO stInfo;
        //stInfo.parCallStack = new STACK_ARRAY;
        
        void * p = AllocMem(sizeof(STACK_ARRAY));
        stInfo.parCallStack = new( (void*)p ) STACK_ARRAY;
        
        stInfo.nMemSize = dwBytes;
        for( int i =0; i < g_StackDepth ; i++ )// only retrieve 40 functions
        {
            BOOL b = StackWalk64( IMAGE_FILE_MACHINE_I386, hProcess, GetCurrentThread(), 
                              &stStackFrame ,&stContext, 0, 
                              SymFunctionTableAccess64 , SymGetModuleBase64, NULL );
            if ( !b )
            {
               break;
            }
            DWORD64 dwDisplacement = 0;
            if (stStackFrame.AddrPC.Offset == stStackFrame.AddrReturn.Offset)
            {
              break;
            }

//////////////////////////////////////////////////////////////////////////
        //if( SymFromAddr( hProcess, stStackFrame.AddrPC.Offset, &dwDisplacement, pSymbol ))
        //{
        //		CString cs = "Ordinal823";
        //	if( cs == pSymbol->Name)
        //		{
        //			break;
        //		}
        //			
        //}
//////////////////////////////////////////////////////////////////////////

            if( i <= 1 )// ignore the functions on the top of stack which is our own.
            {
                continue;
            }
            stInfo.parCallStack->Add( stStackFrame.AddrPC.Offset );
        }        
        m_MemMap[pMem] = stInfo;        
}

#else
void StackDump( LPVOID pMem, SIZE_T dwBytes)
{
        
    CONTEXT                       Context;
    //KNONVOLATILE_CONTEXT_POINTERS NvContext;
    //UNWIND_HISTORY_TABLE          UnwindHistoryTable;
    PRUNTIME_FUNCTION             RuntimeFunction;
    PVOID                         HandlerData;
    ULONG64                       EstablisherFrame;
    ULONG64                       ImageBase;

    //OutputDebugString(L"StackTrace64: Executing stack trace...\n");

    //
    // First, we'll get the caller's context.
    //

    RtlCaptureContext(&Context);

    //
    // Initialize the (optional) unwind history table.
    //

    /*RtlZeroMemory(
        &UnwindHistoryTable,
        sizeof(UNWIND_HISTORY_TABLE));*/

    
        //BYTE SymBol[ sizeof(SYMBOL_INFO) + STACKWALK_MAX_NAMELEN ] = {0};
        //SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)SymBol;
        //DWORD64 dwDisplacement;
     
        HANDLE hProcess = GetCurrentProcess();
        MEM_INFO stInfo;
        //stInfo.parCallStack = new STACK_ARRAY;
        
        void * p = AllocMem(sizeof(STACK_ARRAY));
        stInfo.parCallStack = new( (void*)p ) STACK_ARRAY;
        
        stInfo.nMemSize = dwBytes;
        for( int i =0; i < g_StackDepth ; i++ )// only retrieve 40 functions
        {
            //
        // Try to look up unwind metadata for the current function.
        //

        RuntimeFunction = RtlLookupFunctionEntry(
            Context.Rip,
            &ImageBase,
            NULL
            );

        /*RtlZeroMemory(
            &NvContext,
            sizeof(KNONVOLATILE_CONTEXT_POINTERS));*/

        if (!RuntimeFunction)
        {
            //
            // If we don't have a RUNTIME_FUNCTION, then we've encountered
            // a leaf function.  Adjust the stack approprately.
            //

            Context.Rip  = (ULONG64)(*(PULONG64)Context.Rsp);
            Context.Rsp += 8;
        }
        else
        {
            //
            // Otherwise, call upon RtlVirtualUnwind to execute the unwind for
            // us.
            //

            RtlVirtualUnwind(
                0, //UNW_FLAG_NHANDLER,
                ImageBase,
                Context.Rip,
                RuntimeFunction,
                &Context,
                &HandlerData,
                &EstablisherFrame,
                NULL );
        }

        //
        // If we reach an RIP of zero, this means that we've walked off the end
        // of the call stack and are done.
        //

        if (!Context.Rip)
            break;

//////////////////////////////////////////////////////////////////////////
         
                 //if( SymFromAddr( hProcess, Context.Rip, &dwDisplacement, pSymbol ))
                 //{
                 //    CString cs = "Ordinal823";
                 //     if( cs == pSymbol->Name)
                 //    {
                 //        break;
                 //    }
                 //   
                 //}
//////////////////////////////////////////////////////////////////////////

            if( i <= 1 )// ignore the functions on the top of stack which is our own.
            {
                continue;
            }
            stInfo.parCallStack->Add( Context.Rip );
        }        
        m_MemMap[pMem] = stInfo;        
}
#endif

void CreateCallStack( LPVOID lpMem, SIZE_T dwBytes )
{
    if( !lpMem )
    {
        return;
    }
    try
    {		
        CSingleLock lockObj( &SyncObj, TRUE );
        if( g_bHooked && g_bTrack )
        {
            g_bTrack = false;
            StackDump( lpMem, dwBytes );
#ifdef ENABLE_LOG
            CString cs;
            cs.Format( "Allocating    %x" ,(UINT)lpMem);
            OutputDebugString(cs);
#endif
            g_bTrack = true;
        }
    }
    catch(...)
    {
    }
    
}

void RemovCallStack( LPVOID lpMem )
{
    try
    {
        if( !lpMem )
        {
            return;
        }

        CSingleLock lockObj( &SyncObj, TRUE );
        if( g_bHooked && g_bTrack )
        {
            g_bTrack = false;
            MEM_INFO stInfo;
            if( m_MemMap.Lookup( lpMem, stInfo ))
            {
                //delete stInfo.parCallStack;
                stInfo.parCallStack->~STACK_ARRAY();
                DeleteMem( stInfo.parCallStack);
                m_MemMap.RemoveKey( lpMem );
#ifdef ENABLE_LOG
                CString cs;
                cs.Format( "De-allocating %x" ,(UINT)lpMem);
                OutputDebugString(cs);
#endif
            }
            g_bTrack = true;
        }
    }
    catch(...)
    {
    }	
}

void CopyStack(LPVOID lpExisting, LPVOID lpNew, int nType )
{
    CSingleLock lockObj( &SyncObj, TRUE );
    if( g_bHooked && g_bTrack )
    {
        MEM_INFO stInfo;
        if( m_MemMap.Lookup( lpExisting, stInfo ))
        {
            MEM_INFO stNew;
            //stNew.parCallStack = new STACK_ARRAY;
            void * p = AllocMem(sizeof(STACK_ARRAY));
            stNew.parCallStack = new( (void*)p ) STACK_ARRAY;
            
            stNew.parCallStack->Copy( *stInfo.parCallStack );
            stNew.nMemSize = nType;
        }

    }
}


LPVOID WINAPI MyHeapAlloc( IN HANDLE hHeap,
                           IN DWORD dwFlags,
                           IN SIZE_T dwBytes )
{
    LPVOID lMem =  pOrgHeapAlloc( hHeap, dwFlags, dwBytes );
    CreateCallStack( lMem, dwBytes );
    return lMem;
}

LPVOID WINAPI MyHeapReAlloc( HANDLE hHeap,
                           DWORD dwFlags,
                           LPVOID lpMem,
                           SIZE_T dwBytes )
{
    LPVOID lpNewMem = pOrgHeapReAlloc( hHeap, dwFlags, lpMem, dwBytes );
    try
    {
        CSingleLock lockObj( &SyncObj, TRUE );
        if( g_bHooked && g_bTrack )
        {
            g_bTrack = false;
            MEM_INFO stInfo;
            if( m_MemMap.Lookup( lpMem, stInfo ))
            {				
                m_MemMap.RemoveKey( lpMem );
                m_MemMap[lpNewMem] = stInfo;

            }
            g_bTrack = true;
        }
    }
    catch (...)
    {
    }
    return lpNewMem;
}


LPVOID WINAPI MyVirtualAllocEx( HANDLE hProcess, LPVOID lpAddress,
                                SIZE_T dwSize, DWORD flAllocationType,
                                DWORD flProtect )
{
    LPVOID lMem =  pOrgVirtualAllocEx( hProcess, lpAddress, dwSize, flAllocationType, flProtect );
    CreateCallStack( lMem, dwSize );
    return lMem;
}

BOOL WINAPI MyVirtualFreeEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
    RemovCallStack( lpAddress );
    return pOrgVirtualFreeEx( hProcess, lpAddress, dwSize, dwFreeType );
}

BOOL WINAPI MyHeapFree(  HANDLE hHeap,  DWORD dwFlags,  LPVOID lpMem )
{
    RemovCallStack( lpMem );
    return pOrgHeapFree( hHeap, dwFlags, lpMem );
}


HANDLE WINAPI MyGlobalAlloc( UINT uFlags, SIZE_T dwBytes )
{
	HANDLE hHandle = pOrgGlobalAlloc( uFlags,  dwBytes );
	if ( g_HookType == HT_MEMORY )
		CreateCallStack(hHandle, dwBytes);
	else
		CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
    return hHandle;
}

HANDLE WINAPI MyGlobalReAlloc( HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags )
{
    HANDLE hHandle = pOrgGlobalReAlloc( hMem, dwBytes, uFlags  );
    if( hHandle )
    {
		if ( g_HookType == HT_MEMORY )
			CreateCallStack(hHandle, dwBytes);
		else
			CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
        RemovCallStack( hMem );
    }
    return hHandle;
}

HANDLE WINAPI MyGlobalFree( HGLOBAL hMem )
{
	HANDLE hHandle = pOrgGlobalFree( hMem );
	if ( hHandle == NULL )
		RemovCallStack( hMem );
	return hHandle;

}
HLOCAL WINAPI MyLocalAlloc( UINT uFlags, SIZE_T uBytes )
{
    HLOCAL hHandle = pOrgLocalAlloc( uFlags,  uBytes );
	if ( g_HookType == HT_MEMORY )
		CreateCallStack(hHandle, uBytes);
	else
		CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
    return hHandle;
}

HLOCAL WINAPI MyLocalReAlloc( HLOCAL hMem, SIZE_T uBytes, UINT uFlags )
{
    HLOCAL hHandle = pOrgLocalReAlloc( hMem, uBytes, uFlags);
    if( hHandle )
    {
		if ( g_HookType == HT_MEMORY )
			CreateCallStack(hHandle, uBytes);
		else
			CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
        RemovCallStack( hMem );
    }
    return hHandle;
}

HLOCAL WINAPI MyLocalFree(HLOCAL hMem )
{
	HLOCAL hHandle = pOrgLocalFree(hMem );
	if ( hHandle == NULL )
		RemovCallStack( hMem );
	return hHandle;
}

LPVOID WINAPI MyCoTaskMemAlloc( SIZE_T cb)
{
    LPVOID lpMem = pOrgCoTaskMemAlloc( cb );
    CreateCallStack( lpMem, cb );
    return lpMem;
}

LPVOID WINAPI MyCoTaskMemRealloc(LPVOID pv, SIZE_T cb)
{
    LPVOID lpMem = pOrgCoTaskMemRealloc(pv, cb );
    if( lpMem )
    {
        CreateCallStack( lpMem, cb );
        RemovCallStack( pv );
    }
    return lpMem;
}

void   WINAPI MyCoTaskMemFree( LPVOID pv )
{
    RemovCallStack( pv );
}

//////////////////////////////////////////////////////////////////////////

void HookMemAlloc()
{
    HMODULE hLib = GetModuleHandle( "Kernel32.dll" );
    HMODULE hOleLib = GetModuleHandle( "ole32.dll" );
    pOrgHeapAlloc     = (HeapAllocDef)GetProcAddress( hLib, "HeapAlloc" );    
    pOrgHeapFree = (HeapFreeDef)GetProcAddress( hLib, "HeapFree" );
    pOrgHeapReAlloc = (HeapReAllocDef)GetProcAddress( hLib, "HeapReAlloc" );
    pOrgVirtualAllocEx = (VirtualAllocExDef)GetProcAddress( hLib, "VirtualAllocEx" );    
    pOrgVirtualFreeEx = (VirtualFreeExDef)GetProcAddress( hLib, "VirtualFreeEx" );

    pOrgGlobalAlloc = (GlobalAllocDef)GetProcAddress( hLib, "GlobalAlloc" );
    pOrgGlobalReAlloc = (GlobalReAllocDef)GetProcAddress( hLib, "GlobalReAlloc" );
    pOrgGlobalFree = (GlobalFreeDef)GetProcAddress( hLib, "GlobalFree" );
    pOrgLocalAlloc = (LocalAllocDef)GetProcAddress( hLib, "LocalAlloc" );
    pOrgLocalReAlloc = (LocalReAllocDef)GetProcAddress( hLib, "LocalReAlloc" );
    pOrgLocalFree = (LocalFreeDef)GetProcAddress( hLib, "LocalFree" );

    pOrgCoTaskMemAlloc = (CoTaskMemAllocDef)GetProcAddress( hOleLib, "CoTaskMemAlloc" );
    pOrgCoTaskMemRealloc = (CoTaskMemReallocDef)GetProcAddress( hOleLib, "CoTaskMemRealloc" );
    pOrgCoTaskMemFree = (CoTaskMemFreeDef)GetProcAddress( hOleLib, "CoTaskMemFree" );


    HOOKFUNCDESC stHook[14] = {0};
    int nIndex = 0;
    stHook[nIndex].pProc = (PROC)MyHeapAlloc;
    stHook[nIndex].szFunc = "HeapAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyHeapFree;
    stHook[nIndex].szFunc = "HeapFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyHeapReAlloc;
    stHook[nIndex].szFunc = "HeapAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyVirtualAllocEx;
    stHook[nIndex].szFunc = "VirtualAllocEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyVirtualFreeEx;
    stHook[nIndex].szFunc = "VirtualFreeEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGlobalAlloc;
    stHook[nIndex].szFunc = "GlobalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGlobalReAlloc;
    stHook[nIndex].szFunc = "GlobalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGlobalFree;
    stHook[nIndex].szFunc = "GlobalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLocalAlloc;
    stHook[nIndex].szFunc = "LocalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLocalReAlloc;
    stHook[nIndex].szFunc = "LocalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLocalFree;
    stHook[nIndex].szFunc = "LocalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCoTaskMemAlloc;
    stHook[nIndex].szFunc = "CoTaskMemAlloc";
    stHook[nIndex].lpszDllName = _T("ole32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCoTaskMemRealloc;
    stHook[nIndex].szFunc = "CoTaskMemRealloc";
    stHook[nIndex].lpszDllName = _T("ole32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCoTaskMemFree;
    stHook[nIndex].szFunc = "CoTaskMemFree";
    stHook[nIndex].lpszDllName = _T("ole32.dll");
    nIndex++;

    HookDynamicLoadedFun( nIndex, stHook );
}

void RestoreMemHooks()
{
    HOOKFUNCDESC stHook[14] = {0};
    int nIndex = 0;
    stHook[nIndex].pProc = (PROC)pOrgHeapAlloc;
    stHook[nIndex].szFunc = "HeapAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgHeapFree;
    stHook[nIndex].szFunc = "HeapFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgHeapReAlloc;
    stHook[nIndex].szFunc = "HeapAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgVirtualAllocEx;
    stHook[nIndex].szFunc = "VirtualAllocEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgVirtualFreeEx;
    stHook[nIndex].szFunc = "VirtualFreeEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGlobalAlloc;
    stHook[nIndex].szFunc = "GlobalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGlobalReAlloc;
    stHook[nIndex].szFunc = "GlobalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGlobalFree;
    stHook[nIndex].szFunc = "GlobalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLocalAlloc;
    stHook[nIndex].szFunc = "LocalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLocalReAlloc;
    stHook[nIndex].szFunc = "LocalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLocalFree;
    stHook[nIndex].szFunc = "LocalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCoTaskMemAlloc;
    stHook[nIndex].szFunc = "CoTaskMemAlloc";
    stHook[nIndex].lpszDllName = _T("ole32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCoTaskMemRealloc;
    stHook[nIndex].szFunc = "CoTaskMemRealloc";
    stHook[nIndex].lpszDllName = _T("ole32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCoTaskMemFree;
    stHook[nIndex].szFunc = "CoTaskMemFree";
    stHook[nIndex].lpszDllName = _T("ole32.dll");
    nIndex++;

    HookDynamicLoadedFun( nIndex, stHook );
}

//////////////////////////////////////////////////////////////////////////
                 //gdi functions
//////////////////////////////////////////////////////////////////////////

// bitmap
HBITMAP WINAPI MyLoadBitmapA( HINSTANCE hInstance, LPCSTR lpBitmapName)
{
    HBITMAP hBmp = pOrgLoadBitmapA( hInstance, lpBitmapName );
    CreateCallStack( hBmp , 0 );
    return hBmp;
}
HBITMAP WINAPI MyLoadBitmapW( HINSTANCE hInstance, LPCWSTR lpBitmapName )
{
    HBITMAP hBmp =  pOrgLoadBitmapW( hInstance, lpBitmapName );
    CreateCallStack( hBmp , 0 );
    return hBmp;
}

HANDLE  WINAPI MyLoadImageADef( HINSTANCE hInst, LPCSTR name, UINT type,int cx,int cy, UINT fuLoad)
{
    HANDLE hBmp =  pOrgLoadImageA( hInst, name, type,cx,cy, fuLoad );
    CreateCallStack( hBmp , type );
    return hBmp;
}

HANDLE  WINAPI MyLoadImageWDef( HINSTANCE hInst, LPCWSTR name, UINT type, int cx, int cy, UINT fuLoad)
{
    HANDLE hBmp =  pOrgLoadImageW( hInst, name, type,cx,cy, fuLoad );
    CreateCallStack( hBmp , type );
    return hBmp;
}

HBITMAP WINAPI MyCreateBitmap(  int nWidth,  int nHeight, UINT nPlanes,  UINT nBitCount,  CONST VOID *lpBits)
{
    HBITMAP hBmp =  pOrgCreateBitmap( nWidth,  nHeight, nPlanes,   nBitCount,  lpBits );
    CreateCallStack( hBmp , 0 );
    return hBmp;
}

HBITMAP WINAPI MyCreateBitmapIndirect(  CONST BITMAP *pbm )
{
    HBITMAP hBmp =  pOrgCreateBitmapIndirect( pbm );
    CreateCallStack( hBmp , 0 );
    return hBmp;
}

HBITMAP WINAPI MyCreateCompatibleBitmap(  HDC hdc,  int cx,  int cy)
{
    HBITMAP hBmp =  pOrgCreateCompatibleBitmap( hdc,   cx,   cy);
    CreateCallStack( hBmp , 0 );
    return hBmp;
}

HBITMAP WINAPI MyCreateDIBitmap(  HDC hdc,  CONST BITMAPINFOHEADER *pbmih,  DWORD flInit,  CONST VOID *pjBits,  CONST BITMAPINFO *pbmi,  UINT iUsage)
{
    HBITMAP hBmp =  pOrgCreateDIBitmap( hdc,   pbmih,   flInit,  pjBits,   pbmi,   iUsage);
    CreateCallStack( hBmp , 0 );
    return hBmp;
}

HBITMAP WINAPI MyCreateDIBSection( HDC hdc,  CONST BITMAPINFO *lpbmi,  UINT usage, VOID **ppvBits,  HANDLE hSection,  DWORD offset)
{
    HBITMAP hBmp =  pOrgCreateDIBSection( hdc,  lpbmi,  usage, ppvBits,  hSection,  offset );
    CreateCallStack( hBmp , 0 );
    return hBmp;
}


HBITMAP WINAPI MyCreateDiscardableBitmap( HDC hdc, int cx, int cy)
{
    HBITMAP hBmp =  pOrgCreateDiscardableBitmap( hdc, cx, cy );
    CreateCallStack( hBmp , 0 );
    return hBmp;
}

HANDLE  WINAPI MyCopyImage( HANDLE h, UINT type, int cx, int cy, UINT flags)
{
    HANDLE hBmp =  pOrgCopyImage(h, type, cx, cy, flags);
    int nType = 0;
    CreateCallStack( hBmp , type );
    return hBmp;
}

BOOL WINAPI MyGetIconInfo( HICON hIcon, PICONINFO piconinfo)
{
    BOOL bRet = pOrgGetIconInfo( hIcon, piconinfo );
    if( bRet )
    {
        CreateCallStack( piconinfo->hbmColor, 0 );
        if( piconinfo->hbmMask )
        {
            CSingleLock lockObj( &SyncObj, TRUE );
            if( g_bHooked && g_bTrack )
            {
                g_bTrack = false;
                MEM_INFO stInfo;
                if( m_MemMap.Lookup( piconinfo->hbmColor, stInfo ))
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[piconinfo->hbmMask] = stInfo2;
                }
                g_bTrack = true;
            }
        }
        
    }
    return bRet;
}

BOOL WINAPI MyGetIconInfoExA( HICON hicon, PICONINFOEXA piconinfo)
{
    BOOL bRet = pOrgGetIconInfoExA( hicon, piconinfo );
    if( bRet )
    {
        CreateCallStack( piconinfo->hbmColor, 0 );
        if( piconinfo->hbmMask )
        {
            CSingleLock lockObj( &SyncObj, TRUE );
            if( g_bHooked && g_bTrack )
            {
                g_bTrack = false;
                MEM_INFO stInfo;
                if( m_MemMap.Lookup( piconinfo->hbmColor, stInfo ))
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[piconinfo->hbmMask] = stInfo2;
                }
                g_bTrack = true;
            }
        }

    }
    return bRet;
}

BOOL WINAPI MyGetIconInfoExW( HICON hicon,PICONINFOEXW piconinfo)
{
    BOOL bRet = pOrgGetIconInfoExW( hicon, piconinfo );
    if( bRet )
    {
        CreateCallStack( piconinfo->hbmColor, 0 );
        if( piconinfo->hbmMask )
        {
            CSingleLock lockObj( &SyncObj, TRUE );
            if( g_bHooked && g_bTrack )
            {
                g_bTrack = false;
                MEM_INFO stInfo;
                if( m_MemMap.Lookup( piconinfo->hbmColor, stInfo ))
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[piconinfo->hbmMask] = stInfo2;
                }
                g_bTrack = true;
            }
        }
    }
    return bRet;
}


BOOL WINAPI MyDeleteObject(  HGDIOBJ ho)
{
    BOOL bRet =  pOrgDeleteObject( ho );
    if( bRet )
        RemovCallStack( ho );
    return bRet;
}

//////////////////////////////////////////////////////////////////////////
//ICONS
HICON WINAPI MyCopyIcon( HICON hIcon)
{
    HICON hIconnew = pOrgCopyIcon( hIcon );
    CreateCallStack( hIconnew, IMAGE_ICON );
    return hIconnew;
}

HICON WINAPI MyCreateIcon(HINSTANCE hInstance,int nWidth,int nHeight,BYTE cPlanes,BYTE cBitsPixel,CONST BYTE *lpbANDbits,CONST BYTE *lpbXORbits)
{
    HICON hIcon = pOrgCreateIcon( hInstance,nWidth,nHeight,cPlanes,cBitsPixel,lpbANDbits,lpbXORbits) ;
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyCreateIconFromResource( PBYTE presbits, DWORD dwResSize, BOOL fIcon, DWORD dwVer)
{
    HICON hIcon = pOrgCreateIconFromResource(presbits, dwResSize, fIcon, dwVer);
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyCreateIconFromResourceEx( PBYTE presbits, DWORD dwResSize,BOOL fIcon,DWORD dwVer,int cxDesired,int cyDesired,UINT Flags )
{
    HICON hIcon = pOrgCreateIconFromResourceEx(presbits, dwResSize,fIcon,dwVer,cxDesired,cyDesired,Flags );
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyCreateIconIndirect( PICONINFO piconinfo )
{
    HICON hIcon = pOrgCreateIconIndirect(piconinfo );
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

BOOL  WINAPI MyDestroyIcon(HICON hIcon)
{
    BOOL bRet = pOrgDestroyIcon( hIcon );
    if( bRet )
        RemovCallStack( hIcon );
    return bRet;
}

HICON WINAPI MyDuplicateIcon(HINSTANCE hInst, HICON hIcon)
{
    HICON hIconnew = pOrgDuplicateIcon( hInst, hIcon );
    CreateCallStack( hIconnew, IMAGE_ICON );
    return hIconnew;
}

HICON WINAPI MyExtractAssociatedIconA(HINSTANCE hInst,  LPSTR lpIconPath,  LPWORD lpiIcon)
{
    HICON hIcon = pOrgExtractAssociatedIconA(hInst,  lpIconPath,  lpiIcon);
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyExtractAssociatedIconW(HINSTANCE hInst,  LPWSTR lpIconPath,  LPWORD lpiIcon)
{
    HICON hIcon = pOrgExtractAssociatedIconW(hInst,  lpIconPath,  lpiIcon);
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyExtractAssociatedIconExA(HINSTANCE hInst,LPSTR lpIconPath,  LPWORD lpiIconIndex,  LPWORD lpiIconId)
{
    HICON hIcon = pOrgExtractAssociatedIconExA(hInst,lpIconPath,  lpiIconIndex,  lpiIconId);
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyExtractAssociatedIconExW(HINSTANCE hInst,LPWSTR lpIconPath,  LPWORD lpiIconIndex,  LPWORD lpiIconId)
{
    HICON hIcon = pOrgExtractAssociatedIconExW(hInst,lpIconPath,  lpiIconIndex,  lpiIconId);
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyExtractIconA(HINSTANCE hInst, LPCSTR lpszExeFileName, UINT nIconIndex)
{
    HICON hIcon = pOrgExtractIconA(hInst, lpszExeFileName, nIconIndex);
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

HICON WINAPI MyExtractIconW(HINSTANCE hInst, LPCWSTR lpszExeFileName, UINT nIconIndex)
{
    HICON hIcon = pOrgExtractIconW(hInst, lpszExeFileName, nIconIndex);
    CreateCallStack( hIcon, IMAGE_ICON );
    return hIcon;
}

UINT  WINAPI MyExtractIconExA(LPCSTR lpszFile, int nIconIndex, HICON *phiconLarge, HICON *phiconSmall, UINT nIcons)
{
    UINT uRet = pOrgExtractIconExA(lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
    if( uRet <= 0 || ( -1 == nIconIndex && !phiconLarge && !phiconSmall))
    {
        return uRet;
    }
    MEM_INFO stInfo;	
    CSingleLock lockObj( &SyncObj, TRUE );
    bool bFirst = true;
    if( g_bHooked && g_bTrack )
    {
        g_bTrack = false;			
        for( UINT uIdx = 1; uIdx < uRet; uIdx++ )
        {
            if( phiconLarge[uIdx] )
            {				
                if( bFirst )
                {
                    CreateCallStack( phiconLarge[uIdx], IMAGE_ICON );
                    if( m_MemMap.Lookup( phiconLarge[uIdx], stInfo ))
                        bFirst = false;
                }
                else
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[phiconLarge[uIdx]] = stInfo2;
                }					
            }

            if( phiconSmall[uIdx] )
            {				
                if( bFirst )
                {
                    CreateCallStack( phiconSmall[uIdx], IMAGE_ICON );
                    if( m_MemMap.Lookup( phiconLarge[uIdx], stInfo ))
                        bFirst = false;
                }
                else
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[phiconSmall[uIdx]] = stInfo2;
                }					
            }
        }
        g_bTrack = true;
    }		
    return uRet;
}

UINT  WINAPI MyExtractIconExW(LPCWSTR lpszFile, int nIconIndex,  HICON *phiconLarge, HICON *phiconSmall, UINT nIcons)
{
    UINT uRet = pOrgExtractIconExW(lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
    if( uRet <= 0 || ( -1 == nIconIndex && !phiconLarge && !phiconSmall))
    {
        return uRet;
    }
    MEM_INFO stInfo;	
    CSingleLock lockObj( &SyncObj, TRUE );
    bool bFirst = true;
    if( g_bHooked && g_bTrack )
    {
        g_bTrack = false;			
        for( UINT uIdx = 1; uIdx < uRet; uIdx++ )
        {
            if( phiconLarge[uIdx] )
            {				
                if( bFirst )
                {
                    CreateCallStack( phiconLarge[uIdx], IMAGE_ICON );
                    if( m_MemMap.Lookup( phiconLarge[0], stInfo ))
                        bFirst = false;
                }
                else
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[phiconLarge[uIdx]] = stInfo2;
                }					
            }

            if( phiconSmall[uIdx] )
            {				
                if( bFirst )
                {
                    CreateCallStack( phiconSmall[uIdx], IMAGE_ICON );
                    if( m_MemMap.Lookup( phiconLarge[0], stInfo ))
                        bFirst = false;
                }
                else
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[phiconSmall[uIdx]] = stInfo2;
                }					
            }
        }
        g_bTrack = true;
    }		
    return uRet;
}

HICON WINAPI MyLoadIconA( HINSTANCE hInstance, LPCSTR lpIconName )
{
    HICON hIcon = pOrgLoadIconA(hInstance, lpIconName );
    if( hIcon && hInstance )
    {
        CreateCallStack( hIcon, IMAGE_ICON );
    }
    return hIcon;
}

HICON WINAPI MyLoadIconW( HINSTANCE hInstance, LPCWSTR lpIconName )
{
    HICON hIcon = pOrgLoadIconW(hInstance, lpIconName );
    if( hIcon && hInstance )
    {
        CreateCallStack( hIcon, IMAGE_ICON );
    }
    return hIcon;
}

UINT  WINAPI MyPrivateExtractIconsA( LPCSTR szFileName, int nIconIndex, int cxIcon, int cyIcon, HICON *phicon, UINT *piconid, UINT nIcons, UINT flags)
{
    UINT uRet = pOrgPrivateExtractIconsA(szFileName, nIconIndex, cxIcon, cyIcon, phicon, piconid, nIcons, flags);
    if( uRet <= 0 || !phicon )
    {
        return uRet;
    }
    MEM_INFO stInfo;	
    CSingleLock lockObj( &SyncObj, TRUE );
    bool bFirst = true;
    if( g_bHooked && g_bTrack )
    {
        g_bTrack = false;			
        for( UINT uIdx = 1; uIdx < uRet; uIdx++ )
        {
            if( phicon[uIdx] )
            {				
                if( bFirst )
                {
                    CreateCallStack( phicon[uIdx], IMAGE_ICON );
                    if( m_MemMap.Lookup( phicon[uIdx], stInfo ))
                        bFirst = false;
                }
                else
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[phicon[uIdx]] = stInfo2;
                }					
            }
        }
        g_bTrack = true;
    }		
    return uRet;
}

UINT  WINAPI MyPrivateExtractIconsW( LPCWSTR szFileName, int nIconIndex, int cxIcon, int cyIcon, HICON *phicon, UINT *piconid,UINT nIcons,UINT flags)
{
    UINT uRet = pOrgPrivateExtractIconsW(szFileName, nIconIndex, cxIcon, cyIcon, phicon, piconid, nIcons, flags);
    if( uRet <= 0 || !phicon )
    {
        return uRet;
    }
    MEM_INFO stInfo;	
    CSingleLock lockObj( &SyncObj, TRUE );
    bool bFirst = true;
    if( g_bHooked && g_bTrack )
    {
        g_bTrack = false;			
        for( UINT uIdx = 1; uIdx < uRet; uIdx++ )
        {
            if( phicon[uIdx] )
            {				
                if( bFirst )
                {
                    CreateCallStack( phicon[uIdx], IMAGE_ICON );
                    if( m_MemMap.Lookup( phicon[uIdx], stInfo ))
                        bFirst = false;
                }
                else
                {
                    MEM_INFO stInfo2;
                    stInfo2.nMemSize = stInfo.nMemSize;
                    //stInfo2.parCallStack = new STACK_ARRAY;
                    void * p = AllocMem(sizeof(STACK_ARRAY));
                    stInfo2.parCallStack = new( (void*)p ) STACK_ARRAY;
                    stInfo2.parCallStack->Copy( *stInfo.parCallStack );
                    m_MemMap[phicon[uIdx]] = stInfo2;
                }					
            }
        }
        g_bTrack = true;
    }		
    return uRet;
}


//////////////////////////////////////////////////////////////////////////
// Cursors
HCURSOR WINAPI MyCreateCursor( HINSTANCE hInst, int xHotSpot, int yHotSpot,int nWidth, int nHeight, CONST VOID *pvANDPlane,CONST VOID *pvXORPlane)
{
    HCURSOR hCur = pOrgCreateCursor(hInst, xHotSpot, yHotSpot,nWidth, nHeight, pvANDPlane,pvXORPlane);
    CreateCallStack( hCur, IMAGE_CURSOR);
    return hCur;
}

HCURSOR WINAPI MyLoadCursorA( HINSTANCE hInstance, LPCSTR lpCursorName)
{
    HCURSOR hCur = pOrgLoadCursorA( hInstance, lpCursorName );
    if( hInstance )
    {
        CreateCallStack( hCur, IMAGE_CURSOR );
    }	
    return hCur;
}

HCURSOR WINAPI MyLoadCursorW( HINSTANCE hInstance, LPCWSTR lpCursorName)
{
    HCURSOR hCur = pOrgLoadCursorW( hInstance, lpCursorName );
    if( hInstance )
    {
        CreateCallStack( hCur, IMAGE_CURSOR );
    }	
    return hCur;
}

HCURSOR WINAPI MyLoadCursorFromFileA( LPCSTR lpFileName )
{
    HCURSOR hCur = pOrgLoadCursorFromFileA(lpFileName);
    CreateCallStack( hCur,IMAGE_CURSOR );
    return hCur;
}

HCURSOR WINAPI MyLoadCursorFromFileW( LPCWSTR lpFileName )
{
    HCURSOR hCur = pOrgLoadCursorFromFileW(lpFileName);
    CreateCallStack( hCur, IMAGE_CURSOR );
    return hCur;
}

BOOL WINAPI MyDestroyCursor( HCURSOR hCursor )
{
    BOOL bRet = pOrgDestroyCursor( hCursor );
    if( bRet )
    {
        RemovCallStack( hCursor );
    }
    return bRet;
}

//brush
HBRUSH  WINAPI MyCreateBrushIndirect(  CONST LOGBRUSH *plbrush)
{
    HBRUSH hBr = pOrgCreateBrushIndirect(plbrush);
    CreateCallStack( hBr, 0 );
    return hBr;
}

HBRUSH  WINAPI MyCreateSolidBrush(  COLORREF color)
{
    HBRUSH hBr = pOrgCreateSolidBrush(color);
    CreateCallStack( hBr, 0 );
    return hBr;
}

HBRUSH  WINAPI MyCreatePatternBrush(  HBITMAP hbm)
{
    HBRUSH hBr = pOrgCreatePatternBrush(hbm);
    CreateCallStack( hBr, 0 );
    return hBr;
}

HBRUSH  WINAPI MyCreateDIBPatternBrush(  HGLOBAL h,  UINT iUsage)
{
    HBRUSH hBr = pOrgCreateDIBPatternBrush(h, iUsage );
    CreateCallStack( hBr, 0 );
    return hBr;
}

HBRUSH  WINAPI MyCreateDIBPatternBrushPt(  CONST VOID *lpPackedDIB,  UINT iUsage)
{
    HBRUSH hBr = pOrgCreateDIBPatternBrushPt(lpPackedDIB,iUsage);
    CreateCallStack( hBr, 0 );
    return hBr;
}

HBRUSH  WINAPI MyCreateHatchBrush(  int iHatch,  COLORREF color)
{
    HBRUSH hBr = pOrgCreateHatchBrush( iHatch, color );
    CreateCallStack( hBr, 0 );
    return hBr;
}

// DC functions
 HDC WINAPI MyCreateCompatibleDC( HDC hdc )
 {
    HDC hDC = pOrgCreateCompatibleDC( hdc );
    CreateCallStack( hDC, 0 );
    return hDC;
 }
 
 HDC WINAPI MyCreateDCA( LPCSTR pwszDriver,  LPCSTR pwszDevice,  LPCSTR pszPort,  CONST DEVMODEA * pdm )
 {
    HDC hDC = pOrgCreateDCA( pwszDriver, pwszDevice, pszPort,  pdm );
    CreateCallStack( hDC , 0 );
    return hDC;
 }

 HDC WINAPI MyCreateDCW( LPCWSTR pwszDriver,  LPCWSTR pwszDevice,  LPCWSTR pszPort,  CONST DEVMODEW * pdm )
 {
    HDC hDC = pOrgCreateDCW( pwszDriver, pwszDevice, pszPort,  pdm );
    CreateCallStack( hDC, 0 );
    return hDC;
 }

 HDC WINAPI MyCreateICA( LPCSTR pszDriver,  LPCSTR pszDevice,  LPCSTR pszPort,  CONST DEVMODEA * pdm )
 {
    HDC hDC = pOrgCreateICA( pszDriver, pszDevice, pszPort,  pdm );
    CreateCallStack( hDC, 0 );
    return hDC;
 }

 HDC WINAPI MyCreateICW( LPCWSTR pszDriver,  LPCWSTR pszDevice,  LPCWSTR pszPort,  CONST DEVMODEW * pdm )
 {
    HDC hDC = pOrgCreateICW( pszDriver, pszDevice, pszPort,  pdm );
    CreateCallStack( hDC, 0 );
    return hDC;
 }

 HDC WINAPI MyGetDC( HWND hWnd )
 {
    HDC hDC = pOrgGetDC( hWnd );
    CreateCallStack( hDC, 0 );
    return hDC;
 }

 HDC WINAPI MyGetDCEx( HWND hWnd, HRGN hrgnClip, DWORD flags )
 {
    HDC hDC = pOrgGetDCEx(  hWnd, hrgnClip, flags );
    CreateCallStack( hDC, 0 );
    return hDC;
 }

 HDC WINAPI MyGetWindowDC( HWND hWnd )
 {
    HDC hDC = pOrgGetWindowDC( hWnd );
    CreateCallStack( hDC, 0 );
    return hDC;
 }


int WINAPI MyReleaseDC( HWND hWnd, HDC hDC)
{
    int nRet = pOrgReleaseDC( hWnd, hDC );
    if( nRet )
        RemovCallStack( hDC );
    return nRet;
}

BOOL WINAPI MyDeleteDC( HDC hdc)
{
    BOOL bRet = pOrgDeleteDC( hdc );
    if( bRet )
    {
        RemovCallStack( hdc );
    }	
    return bRet;
}

 // font functions
 HFONT WINAPI MyCreateFontA(  int cHeight,  int cWidth,  int cEscapement,  int cOrientation,  int cWeight,  DWORD bItalic,
     DWORD bUnderline,  DWORD bStrikeOut,  DWORD iCharSet,  DWORD iOutPrecision,  DWORD iClipPrecision,
     DWORD iQuality,  DWORD iPitchAndFamily, LPCSTR pszFaceName)
 {
    HFONT hFont = pOrgCreateFontA( cHeight,  cWidth,  cEscapement,  cOrientation,   cWeight,   bItalic,
          bUnderline,   bStrikeOut,   iCharSet,   iOutPrecision,   iClipPrecision,
          iQuality,   iPitchAndFamily,  pszFaceName );
    CreateCallStack( hFont, 0 );
    return hFont;
 }

 HFONT WINAPI MyCreateFontW(  int cHeight,  int cWidth,  int cEscapement,  int cOrientation,  int cWeight,  DWORD bItalic,
     DWORD bUnderline,  DWORD bStrikeOut,  DWORD iCharSet,  DWORD iOutPrecision,  DWORD iClipPrecision,
     DWORD iQuality,  DWORD iPitchAndFamily, LPCWSTR pszFaceName)
 {

     HFONT hFont = pOrgCreateFontW( cHeight,  cWidth,  cEscapement,  cOrientation,   cWeight,   bItalic,
         bUnderline,   bStrikeOut,   iCharSet,   iOutPrecision,   iClipPrecision,
         iQuality,   iPitchAndFamily,  pszFaceName );
     CreateCallStack( hFont, 0 );
     return hFont;
 }

 HFONT WINAPI MyCreateFontIndirectA(  CONST LOGFONTA *lplf)
 {
     HFONT hFont = pOrgCreateFontIndirectA( lplf );
     CreateCallStack( hFont, 0 );
     return hFont;
 }

 HFONT WINAPI MyCreateFontIndirectW( CONST LOGFONTW *lplf)
 {
     HFONT hFont = pOrgCreateFontIndirectW( lplf );
     CreateCallStack( hFont, 0 );
     return hFont;
 }

 // Meta File
HDC WINAPI MyCreateMetaFileA(  LPCSTR pszFile )
{
    HDC hDC = pOrgCreateMetaFileA( pszFile );
    CreateCallStack( hDC, 0 );
    return hDC;
}

HDC WINAPI MyCreateMetaFileW(  LPCWSTR pszFile )
{
    HDC hDC = pOrgCreateMetaFileW( pszFile );
    CreateCallStack( hDC, 0 );
    return hDC;
}

HDC WINAPI MyCreateEnhMetaFileA(  HDC hdc,  LPCSTR lpFilename,  CONST RECT *lprc,  LPCSTR lpDesc)
{
    HDC hDC = pOrgCreateEnhMetaFileA( hdc, lpFilename, lprc, lpDesc );
    CreateCallStack( hDC, 0 );
    return hDC;
}

HDC WINAPI MyCreateEnhMetaFileW(  HDC hdc,  LPCWSTR lpFilename,  CONST RECT *lprc,  LPCWSTR lpDesc)
{
    HDC hDC = pOrgCreateEnhMetaFileW( hdc, lpFilename, lprc, lpDesc );
    CreateCallStack( hDC, 0 );
    return hDC;

}
HENHMETAFILE WINAPI MyGetEnhMetaFileA(  LPCSTR lpName )
{
    HENHMETAFILE hMetaFile = pOrgGetEnhMetaFileA( lpName );
    CreateCallStack( hMetaFile, 0 );
    return hMetaFile;
}

HENHMETAFILE WINAPI MyGetEnhMetaFileW(  LPCWSTR lpName )
{
    HENHMETAFILE hMetaFile = pOrgGetEnhMetaFileW( lpName );
    CreateCallStack( hMetaFile, 0 );
    return hMetaFile;

}
HMETAFILE WINAPI MyGetMetaFileA(  LPCSTR lpName)
{
    HMETAFILE hMetaFile = pOrgGetMetaFileA( lpName );
    CreateCallStack( hMetaFile, 0 );
    return hMetaFile;
}

HMETAFILE WINAPI MyGetMetaFileW( LPCWSTR lpName )
{
    HMETAFILE hMetaFile = pOrgGetMetaFileW( lpName );
    CreateCallStack( hMetaFile, 0 );
    return hMetaFile ;

}
BOOL WINAPI MyDeleteMetaFile( HMETAFILE hmf )
{
    BOOL bRet = pOrgDeleteMetaFile( hmf );
    if( bRet )
    RemovCallStack( hmf );
    return bRet;
}

BOOL WINAPI MyDeleteEnhMetaFile( HENHMETAFILE hmf )
{
    BOOL bRet = pOrgDeleteEnhMetaFile( hmf );
    if( bRet )
    {
        RemovCallStack( hmf );
    }	
    return bRet;

}
HENHMETAFILE WINAPI MyCopyEnhMetaFileA( HENHMETAFILE hEnh, LPCSTR lpFileName)
{
    HENHMETAFILE hMetaFile = pOrgCopyEnhMetaFileA( hEnh, lpFileName );
    CreateCallStack( hMetaFile , 0 );
    return hMetaFile;
}

HENHMETAFILE WINAPI MyCopyEnhMetaFileW( HENHMETAFILE hEnh, LPCWSTR lpFileName)
{
    HENHMETAFILE hMetaFile = pOrgCopyEnhMetaFileW( hEnh, lpFileName );
    CreateCallStack( hMetaFile, 0 );
    return hMetaFile;
}

HENHMETAFILE WINAPI MyCloseEnhMetaFile( HDC hdc)
{
    HENHMETAFILE hMetaFile = pOrgCloseEnhMetaFile( hdc );
    if( hMetaFile )
    {
        RemovCallStack( hdc );
        CreateCallStack( hMetaFile, 0 );
    }
    return hMetaFile;
}

HMETAFILE WINAPI MyCloseMetaFile( HDC hdc)
{
    HMETAFILE hMetaFile = pOrgCloseMetaFile( hdc );
    if( hMetaFile )
    {
        RemovCallStack( hdc );
        CreateCallStack( hMetaFile, 0 );
    }	
    return hMetaFile;
}


// Pen
HPEN WINAPI MyCreatePen(  int iStyle,  int cWidth,  COLORREF color)
{
    HPEN hGDIObj = pOrgCreatePen( iStyle, cWidth, color );
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HPEN WINAPI MyCreatePenIndirect(  CONST LOGPEN *plpen)
{

    HPEN hGDIObj = pOrgCreatePenIndirect( plpen );
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HPEN WINAPI MyExtCreatePen( DWORD iPenStyle, DWORD cWidth, CONST LOGBRUSH *plbrush, DWORD cStyle, CONST DWORD *pstyle)
{
    HPEN hGDIObj = pOrgExtCreatePen( iPenStyle, cWidth, plbrush, cStyle, pstyle );
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}


// region 
HRGN WINAPI MyPathToRegion( HDC hdc)
{
    HRGN hGDIObj = pOrgPathToRegion(hdc);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyCreateEllipticRgn(  int x1,  int y1,  int x2, int y2)
{
    HRGN hGDIObj = pOrgCreateEllipticRgn( x1, y1, x2, y2 );
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyCreateEllipticRgnIndirect(  CONST RECT *lprect)
{
    HRGN hGDIObj = pOrgCreateEllipticRgnIndirect(lprect);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyCreatePolygonRgn( CONST POINT *pptl, int cPoint, int iMode)
{
    HRGN hGDIObj = pOrgCreatePolygonRgn(pptl,cPoint,iMode);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyCreatePolyPolygonRgn( CONST POINT *pptl, CONST INT  *pc, int cPoly, int iMode)
{
    HRGN hGDIObj = pOrgCreatePolyPolygonRgn(pptl,pc,cPoly,iMode);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyCreateRectRgn(  int x1,  int y1,  int x2,  int y2)
{
    HRGN hGDIObj = pOrgCreateRectRgn(x1,y1,x2,y2);
    CreateCallStack(hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyCreateRectRgnIndirect(  CONST RECT *lprect)
{
    HRGN hGDIObj = pOrgCreateRectRgnIndirect(lprect);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyCreateRoundRectRgn(  int x1,  int y1,  int x2,  int y2,  int w,  int h)
{
    HRGN hGDIObj = pOrgCreateRoundRectRgn(x1,y1,x2,y2,w,h);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HRGN WINAPI MyExtCreateRegion( CONST XFORM * lpx,  DWORD nCount, CONST RGNDATA * lpData)
{
    HRGN hGDIObj = pOrgExtCreateRegion(lpx,nCount,lpData);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

 
//palette 
HPALETTE WINAPI MyCreateHalftonePalette(  HDC hdc)
{
    HPALETTE hGDIObj = pOrgCreateHalftonePalette(hdc);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}

HPALETTE WINAPI MyCreatePalette( CONST LOGPALETTE * plpal )
{
    HPALETTE hGDIObj = pOrgCreatePalette(plpal);
    CreateCallStack( hGDIObj, 0 );
    return hGDIObj;
}


void HookGDIAlloc()
{
    HMODULE hGDIModule = LoadLibrary( "Gdi32.dll" );
    HMODULE hUser32Module = LoadLibrary( "User32.dll" );
    HMODULE hShell32Module = LoadLibrary( "Shell32.dll" );
    
    // Bitmap functions
    pOrgLoadBitmapA = (LoadBitmapADef)GetProcAddress( hUser32Module, "LoadBitmapA" );
    pOrgLoadBitmapW = (LoadBitmapWDef)GetProcAddress( hUser32Module, "LoadBitmapW" );
    pOrgLoadImageA = (LoadImageADef)GetProcAddress( hUser32Module, "LoadImageA" );
    pOrgLoadImageW = (LoadImageWDef)GetProcAddress( hUser32Module, "LoadImageW" );
    pOrgCreateBitmap = (CreateBitmapDef)GetProcAddress( hGDIModule, "CreateBitmap" );
    pOrgCreateBitmapIndirect = (CreateBitmapIndirectDef)GetProcAddress( hGDIModule, "CreateBitmapIndirect" );
    pOrgCreateCompatibleBitmap = (CreateCompatibleBitmapDef)GetProcAddress( hGDIModule, "CreateCompatibleBitmap" );
    pOrgCreateDIBitmap = (CreateDIBitmapDef)GetProcAddress( hGDIModule, "CreateDIBitmap" );
    pOrgCreateDIBSection = (CreateDIBSectionDef)GetProcAddress( hGDIModule, "CreateDIBSection" );
    pOrgCreateDiscardableBitmap =  (CreateDiscardableBitmapDef)GetProcAddress( hGDIModule, "CreateDiscardableBitmap" );
    pOrgCopyImage = (CopyImageDef)GetProcAddress( hUser32Module, "CopyImage" );
    pOrgGetIconInfo = (GetIconInfoDef)GetProcAddress( hUser32Module, "GetIconInfo" );
    pOrgGetIconInfoExA = (GetIconInfoExADef)GetProcAddress( hUser32Module, "GetIconInfoExA" );
    pOrgGetIconInfoExW = (GetIconInfoExWDef)GetProcAddress( hUser32Module, "GetIconInfoExA" );
    pOrgDeleteObject = (DeleteObjectDef)GetProcAddress( hGDIModule, "DeleteObject" );
    
    //ICONS
    pOrgCopyIcon = (CopyIconDef)GetProcAddress( hUser32Module, "CopyIcon" );
    pOrgCreateIcon = (CreateIconDef)GetProcAddress( hUser32Module, "CreateIcon" );
    pOrgCreateIconFromResource = (CreateIconFromResourceDef)GetProcAddress( hUser32Module, "CreateIconFromResource" );
    pOrgCreateIconFromResourceEx = (CreateIconFromResourceExDef)GetProcAddress( hUser32Module, "CreateIconFromResourceEx" );
    pOrgCreateIconIndirect = (CreateIconIndirectDef)GetProcAddress( hUser32Module, "CreateIconIndirect" );
    pOrgDestroyIcon = (DestroyIconDef)GetProcAddress( hUser32Module, "DestroyIcon" );
    pOrgDuplicateIcon = (DuplicateIconDef)GetProcAddress( hShell32Module, "DuplicateIcon" );
    pOrgExtractAssociatedIconA = (ExtractAssociatedIconADef)GetProcAddress( hShell32Module, "ExtractAssociatedIconA" );
    pOrgExtractAssociatedIconW = (ExtractAssociatedIconWDef)GetProcAddress( hShell32Module, "ExtractAssociatedIconW" );
    pOrgExtractAssociatedIconExA = (ExtractAssociatedIconExADef)GetProcAddress( hShell32Module, "ExtractAssociatedIconExA" );
    pOrgExtractAssociatedIconExW = (ExtractAssociatedIconExWDef)GetProcAddress( hShell32Module, "ExtractAssociatedIconExW" );
    pOrgExtractIconA = (ExtractIconADef)GetProcAddress( hShell32Module, "ExtractIconA" );
    pOrgExtractIconW = (ExtractIconWDef)GetProcAddress( hShell32Module, "ExtractIconW" );
    pOrgExtractIconExA = (ExtractIconExADef)GetProcAddress( hShell32Module, "ExtractIconExA" );
    pOrgExtractIconExW = (ExtractIconExWDef)GetProcAddress( hShell32Module, "ExtractIconExW" );
    pOrgLoadIconA = (LoadIconADef)GetProcAddress( hUser32Module, "LoadIconA" );
    pOrgLoadIconW = (LoadIconWDef)GetProcAddress( hUser32Module, "LoadIconW" );
    pOrgPrivateExtractIconsA = (PrivateExtractIconsADef)GetProcAddress( hUser32Module, "PrivateExtractIconsA" );
    pOrgPrivateExtractIconsW = (PrivateExtractIconsWDef)GetProcAddress( hUser32Module, "PrivateExtractIconsW" );

    // Cursor
    pOrgCreateCursor = (CreateCursorDef)GetProcAddress( hUser32Module, "CreateCursor" );
    pOrgLoadCursorA = (LoadCursorADef)GetProcAddress( hUser32Module, "LoadCursorA" );
    pOrgLoadCursorW = (LoadCursorWDef)GetProcAddress( hUser32Module, "LoadCursorW" );
    pOrgLoadCursorFromFileA = (LoadCursorFromFileADef)GetProcAddress( hUser32Module, "LoadCursorFromFileA" );
    pOrgLoadCursorFromFileW = (LoadCursorFromFileWDef)GetProcAddress( hUser32Module, "LoadCursorFromFileW" );
    pOrgDestroyCursor = (DestroyCursorDef)GetProcAddress( hUser32Module, "DestroyCursor" );


    // brush
    pOrgCreateBrushIndirect = (CreateBrushIndirectDef)GetProcAddress( hGDIModule, "CreateBrushIndirect" );
    pOrgCreateSolidBrush = (CreateSolidBrushDef)GetProcAddress( hGDIModule, "CreateSolidBrush" );
    pOrgCreatePatternBrush = (CreatePatternBrushDef)GetProcAddress( hGDIModule, "CreatePatternBrush" );
    pOrgCreateDIBPatternBrush = (CreateDIBPatternBrushDef)GetProcAddress( hGDIModule, "CreateDIBPatternBrush" );
    pOrgCreateDIBPatternBrushPt = (CreateDIBPatternBrushPtDef)GetProcAddress( hGDIModule, "CreateDIBPatternBrushPt" );
    pOrgCreateHatchBrush = (CreateHatchBrushDef)GetProcAddress( hGDIModule, "CreateHatchBrush" );

    // DC
    pOrgCreateCompatibleDC = (CreateCompatibleDCDef)GetProcAddress( hGDIModule, "CreateCompatibleDC" );
    pOrgCreateDCA = (CreateDCADef)GetProcAddress( hGDIModule, "CreateDCA" );
    pOrgCreateDCW = (CreateDCWDef)GetProcAddress( hGDIModule, "CreateDCW" );
    pOrgCreateICA = (CreateICADef)GetProcAddress( hGDIModule, "CreateICA" );
    pOrgCreateICW = (CreateICWDef)GetProcAddress( hGDIModule, "CreateICW" );
    pOrgGetDC	  = (GetDCDef)GetProcAddress( hUser32Module, "GetDC" );
    pOrgGetDCEx   = (GetDCExDef)GetProcAddress( hUser32Module, "GetDCEx" );
    pOrgGetWindowDC = (GetWindowDCDef)GetProcAddress( hUser32Module, "GetWindowDC" );
    pOrgReleaseDC = (ReleaseDCDef)GetProcAddress( hUser32Module, "ReleaseDC" );
    pOrgDeleteDC = (DeleteDCDef)GetProcAddress( hGDIModule, "DeleteDC" );
    

    // FONT
    pOrgCreateFontA = (CreateFontADef)GetProcAddress( hGDIModule, "CreateFontA" );
    pOrgCreateFontW = (CreateFontWDef)GetProcAddress( hGDIModule, "CreateFontW" );
    pOrgCreateFontIndirectA = (CreateFontIndirectADef)GetProcAddress( hGDIModule, "CreateFontIndirectA" );
    pOrgCreateFontIndirectW = (CreateFontIndirectWDef)GetProcAddress( hGDIModule, "CreateFontIndirectW" );

    // Metafile
    pOrgCreateMetaFileA = (CreateMetaFileADef)GetProcAddress( hGDIModule, "CreateMetaFileA" );
    pOrgCreateMetaFileW = (CreateMetaFileWDef)GetProcAddress( hGDIModule, "CreateMetaFileW" );
    pOrgCreateEnhMetaFileA = (CreateEnhMetaFileADef)GetProcAddress( hGDIModule, "CreateEnhMetaFileA" );
    pOrgCreateEnhMetaFileW = (CreateEnhMetaFileWDef)GetProcAddress( hGDIModule, "CreateEnhMetaFileW" );
    pOrgGetEnhMetaFileA = (GetEnhMetaFileADef)GetProcAddress( hGDIModule, "GetEnhMetaFileA" );
    pOrgGetEnhMetaFileW = (GetEnhMetaFileWDef)GetProcAddress( hGDIModule, "GetEnhMetaFileW" );
    pOrgGetMetaFileA = (GetMetaFileADef)GetProcAddress( hGDIModule, "GetMetaFileA" );
    pOrgGetMetaFileW = (GetMetaFileWDef)GetProcAddress( hGDIModule, "GetMetaFileW" );
    pOrgDeleteMetaFile = (DeleteMetaFileDef)GetProcAddress( hGDIModule, "DeleteMetaFile" );
    pOrgDeleteEnhMetaFile = (DeleteEnhMetaFileDef)GetProcAddress( hGDIModule, "DeleteEnhMetaFile" );
    pOrgCopyEnhMetaFileA = (CopyEnhMetaFileADef)GetProcAddress( hGDIModule, "CopyEnhMetaFileA" );
    pOrgCopyEnhMetaFileW = (CopyEnhMetaFileWDef)GetProcAddress( hGDIModule, "CopyEnhMetaFileW" );
    pOrgCloseEnhMetaFile = (CloseEnhMetaFileDef)GetProcAddress( hGDIModule, "CloseEnhMetaFile" );
    pOrgCloseMetaFile = (CloseMetaFileDef)GetProcAddress( hGDIModule, "CloseMetaFile" );

    //Pen
    pOrgCreatePen = (CreatePenDef)GetProcAddress( hGDIModule, "CreatePen" );
    pOrgCreatePenIndirect = (CreatePenIndirectDef)GetProcAddress( hGDIModule, "CreatePenIndirect" );
    pOrgExtCreatePen = (ExtCreatePenDef)GetProcAddress( hGDIModule, "ExtCreatePen" );

    //region
    pOrgPathToRegion = (PathToRegionDef)GetProcAddress( hGDIModule, "PathToRegion" );
    pOrgCreateEllipticRgn = (CreateEllipticRgnDef)GetProcAddress( hGDIModule, "CreateEllipticRgn" );
    pOrgCreateEllipticRgnIndirect = (CreateEllipticRgnIndirectDef)GetProcAddress( hGDIModule, "CreateEllipticRgnIndirect" );
    pOrgCreatePolygonRgn = (CreatePolygonRgnDef)GetProcAddress( hGDIModule, "CreatePolygonRgn" );
    pOrgCreatePolyPolygonRgn = (CreatePolyPolygonRgnDef)GetProcAddress( hGDIModule, "CreatePolyPolygonRgn" );
    pOrgCreateRectRgn = (CreateRectRgnDef)GetProcAddress( hGDIModule, "CreateRectRgn" );
    pOrgCreateRectRgnIndirect = (CreateRectRgnIndirectDef)GetProcAddress( hGDIModule, "CreateRectRgnIndirect" );
    pOrgCreateRoundRectRgn = (CreateRoundRectRgnDef)GetProcAddress( hGDIModule, "CreateRoundRectRgn" );
    pOrgExtCreateRegion = (ExtCreateRegionDef)GetProcAddress( hGDIModule, "ExtCreateRegion" );

    //palette
    pOrgCreateHalftonePalette = (CreateHalftonePaletteDef)GetProcAddress( hGDIModule, "CreateHalftonePalette" );
    pOrgCreatePalette = (CreatePaletteDef)GetProcAddress( hGDIModule, "CreatePalette" );

    HOOKFUNCDESC stHook[86] = {0};
    int nIndex = 0;
    stHook[nIndex].pProc = (PROC)MyLoadBitmapA;
    stHook[nIndex].szFunc = "LoadBitmapA";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLoadBitmapW;
    stHook[nIndex].szFunc = "LoadBitmapW";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateBitmap;
    stHook[nIndex].szFunc = "CreateBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateBitmapIndirect;
    stHook[nIndex].szFunc = "CreateBitmapIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateCompatibleBitmap;
    stHook[nIndex].szFunc = "CreateCompatibleBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateDIBitmap;
    stHook[nIndex].szFunc = "CreateDIBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateDIBSection;
    stHook[nIndex].szFunc = "CreateDIBSection";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateDiscardableBitmap;
    stHook[nIndex].szFunc = "CreateDiscardableBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCopyImage;
    stHook[nIndex].szFunc = "CopyImage";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetIconInfo;
    stHook[nIndex].szFunc = "GetIconInfo";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetIconInfoExA;
    stHook[nIndex].szFunc = "GetIconInfoExA";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetIconInfoExW;
    stHook[nIndex].szFunc = "GetIconInfoExW";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteObject;
    stHook[nIndex].szFunc = "DeleteObject";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    //ICONS
    stHook[nIndex].pProc = (PROC)MyCopyIcon;
    stHook[nIndex].szFunc = "CopyIcon";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateIcon;
    stHook[nIndex].szFunc = "CreateIcon";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateIconFromResource;
    stHook[nIndex].szFunc = "CreateIconFromResource";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateIconFromResourceEx;
    stHook[nIndex].szFunc = "CreateIconFromResourceEx";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateIconIndirect;
    stHook[nIndex].szFunc = "CreateIconIndirect";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDuplicateIcon;
    stHook[nIndex].szFunc = "DuplicateIcon";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDestroyIcon;
    stHook[nIndex].szFunc = "DestroyIcon";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtractAssociatedIconA;
    stHook[nIndex].szFunc = "ExtractAssociatedIconA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtractAssociatedIconW;
    stHook[nIndex].szFunc = "ExtractAssociatedIconW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtractAssociatedIconExA;
    stHook[nIndex].szFunc = "ExtractAssociatedIconExA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtractAssociatedIconExW;
    stHook[nIndex].szFunc = "ExtractAssociatedIconExW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtractIconA;
    stHook[nIndex].szFunc = "ExtractIconA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    
    stHook[nIndex].pProc = (PROC)MyExtractIconW;
    stHook[nIndex].szFunc = "ExtractIconW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtractIconExA;
    stHook[nIndex].szFunc = "ExtractIconExA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtractIconExW;
    stHook[nIndex].szFunc = "ExtractIconExW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLoadIconA;
    stHook[nIndex].szFunc = "LoadIconA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLoadIconW;
    stHook[nIndex].szFunc = "LoadIconW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyPrivateExtractIconsA;
    stHook[nIndex].szFunc = "PrivateExtractIconsA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyPrivateExtractIconsW;
    stHook[nIndex].szFunc = "PrivateExtractIconsW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    // Cursor
    stHook[nIndex].pProc = (PROC)MyCreateCursor;
    stHook[nIndex].szFunc = "CreateCursor";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLoadCursorA;
    stHook[nIndex].szFunc = "LoadCursorA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLoadCursorW;
    stHook[nIndex].szFunc = "LoadCursorW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLoadCursorFromFileA;
    stHook[nIndex].szFunc = "LoadCursorFromFileA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLoadCursorFromFileW;
    stHook[nIndex].szFunc = "LoadCursorFromFileW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDestroyCursor;
    stHook[nIndex].szFunc = "DestroyCursor";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;


    // brush
    stHook[nIndex].pProc = (PROC)MyCreateBrushIndirect;
    stHook[nIndex].szFunc = "CreateBrushIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateSolidBrush;
    stHook[nIndex].szFunc = "CreateSolidBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreatePatternBrush;
    stHook[nIndex].szFunc = "CreatePatternBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateDIBPatternBrush;
    stHook[nIndex].szFunc = "CreateDIBPatternBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateDIBPatternBrushPt;
    stHook[nIndex].szFunc = "CreateDIBPatternBrushPt";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateHatchBrush;
    stHook[nIndex].szFunc = "CreateHatchBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // DC creation
    stHook[nIndex].pProc = (PROC)MyCreateCompatibleDC;
    stHook[nIndex].szFunc = "CreateCompatibleDC";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateDCA;
    stHook[nIndex].szFunc = "CreateDCA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateDCW;
    stHook[nIndex].szFunc = "CreateDCW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateICA;
    stHook[nIndex].szFunc = "CreateICA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateICW;
    stHook[nIndex].szFunc = "CreateICW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetDC;
    stHook[nIndex].szFunc = "GetDC";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetDCEx;
    stHook[nIndex].szFunc = "GetDCEx";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetWindowDC;
    stHook[nIndex].szFunc = "GetWindowDC";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyReleaseDC;
    stHook[nIndex].szFunc = "ReleaseDC";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteDC;
    stHook[nIndex].szFunc = "DeleteDC";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    //Font
    stHook[nIndex].pProc = (PROC)MyCreateFontA;
    stHook[nIndex].szFunc = "CreateFontA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFontW;
    stHook[nIndex].szFunc = "CreateFontW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;
    
    stHook[nIndex].pProc = (PROC)MyCreateFontIndirectA;
    stHook[nIndex].szFunc = "CreateFontIndirectA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFontIndirectW;
    stHook[nIndex].szFunc = "CreateFontIndirectW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // Meta file
    stHook[nIndex].pProc = (PROC)MyCreateMetaFileA;
    stHook[nIndex].szFunc = "CreateMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMetaFileW;
    stHook[nIndex].szFunc = "CreateMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateEnhMetaFileA;
    stHook[nIndex].szFunc = "CreateEnhMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateEnhMetaFileW;
    stHook[nIndex].szFunc = "CreateEnhMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetEnhMetaFileA;
    stHook[nIndex].szFunc = "GetEnhMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetEnhMetaFileW;
    stHook[nIndex].szFunc = "GetEnhMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetMetaFileA;
    stHook[nIndex].szFunc = "GetMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGetMetaFileW;
    stHook[nIndex].szFunc = "GetMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteMetaFile;
    stHook[nIndex].szFunc = "DeleteMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteEnhMetaFile;
    stHook[nIndex].szFunc = "DeleteEnhMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCopyEnhMetaFileA;
    stHook[nIndex].szFunc = "CopyEnhMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCopyEnhMetaFileW;
    stHook[nIndex].szFunc = "CopyEnhMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCloseEnhMetaFile;
    stHook[nIndex].szFunc = "CloseEnhMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCloseMetaFile;
    stHook[nIndex].szFunc = "CloseMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    //pen
    stHook[nIndex].pProc = (PROC)MyCreatePen;
    stHook[nIndex].szFunc = "CreatePen";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreatePenIndirect;
    stHook[nIndex].szFunc = "CreatePenIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtCreatePen;
    stHook[nIndex].szFunc = "ExtCreatePen";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // rgn
    stHook[nIndex].pProc = (PROC)MyPathToRegion;
    stHook[nIndex].szFunc = "PathToRegion";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateEllipticRgn;
    stHook[nIndex].szFunc = "CreateEllipticRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateEllipticRgnIndirect;
    stHook[nIndex].szFunc = "CreateEllipticRgnIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreatePolygonRgn;
    stHook[nIndex].szFunc = "CreatePolygonRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreatePolyPolygonRgn;
    stHook[nIndex].szFunc = "CreatePolyPolygonRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateRectRgn;
    stHook[nIndex].szFunc = "CreateRectRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateRectRgnIndirect;
    stHook[nIndex].szFunc = "CreateRectRgnIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateRoundRectRgn;
    stHook[nIndex].szFunc = "CreateRoundRectRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyExtCreateRegion;
    stHook[nIndex].szFunc = "ExtCreateRegion";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // Palette
    stHook[nIndex].pProc = (PROC)MyCreateHalftonePalette;
    stHook[nIndex].szFunc = "CreateHalftonePalette";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreatePalette;
    stHook[nIndex].szFunc = "CreatePalette";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    HookDynamicLoadedFun( nIndex, stHook );

}

void RestoreGDIHook()
{
    HOOKFUNCDESC stHook[86] = {0};
    int nIndex = 0;
    stHook[nIndex].pProc = (PROC)pOrgLoadBitmapA;
    stHook[nIndex].szFunc = "LoadBitmapA";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLoadBitmapW;
    stHook[nIndex].szFunc = "LoadBitmapW";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateBitmap;
    stHook[nIndex].szFunc = "CreateBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateBitmapIndirect;
    stHook[nIndex].szFunc = "CreateBitmapIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateCompatibleBitmap;
    stHook[nIndex].szFunc = "CreateCompatibleBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateDIBitmap;
    stHook[nIndex].szFunc = "CreateDIBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateDIBSection;
    stHook[nIndex].szFunc = "CreateDIBSection";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateDiscardableBitmap;
    stHook[nIndex].szFunc = "CreateDiscardableBitmap";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCopyImage;
    stHook[nIndex].szFunc = "CopyImage";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetIconInfo;
    stHook[nIndex].szFunc = "GetIconInfo";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetIconInfoExA;
    stHook[nIndex].szFunc = "GetIconInfoExA";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetIconInfoExW;
    stHook[nIndex].szFunc = "GetIconInfoExW";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteObject;
    stHook[nIndex].szFunc = "DeleteObject";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    //ICONS
    stHook[nIndex].pProc = (PROC)pOrgCopyIcon;
    stHook[nIndex].szFunc = "CopyIcon";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateIcon;
    stHook[nIndex].szFunc = "CreateIcon";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateIconFromResource;
    stHook[nIndex].szFunc = "CreateIconFromResource";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateIconFromResourceEx;
    stHook[nIndex].szFunc = "CreateIconFromResourceEx";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateIconIndirect;
    stHook[nIndex].szFunc = "CreateIconIndirect";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDuplicateIcon;
    stHook[nIndex].szFunc = "DuplicateIcon";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDestroyIcon;
    stHook[nIndex].szFunc = "DestroyIcon";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtractAssociatedIconA;
    stHook[nIndex].szFunc = "ExtractAssociatedIconA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtractAssociatedIconW;
    stHook[nIndex].szFunc = "ExtractAssociatedIconW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtractAssociatedIconExA;
    stHook[nIndex].szFunc = "ExtractAssociatedIconExA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtractAssociatedIconExW;
    stHook[nIndex].szFunc = "ExtractAssociatedIconExW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtractIconA;
    stHook[nIndex].szFunc = "ExtractIconA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;


    stHook[nIndex].pProc = (PROC)pOrgExtractIconW;
    stHook[nIndex].szFunc = "ExtractIconW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtractIconExA;
    stHook[nIndex].szFunc = "ExtractIconExA";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtractIconExW;
    stHook[nIndex].szFunc = "ExtractIconExW";
    stHook[nIndex].lpszDllName = _T("shell32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLoadIconA;
    stHook[nIndex].szFunc = "LoadIconA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLoadIconW;
    stHook[nIndex].szFunc = "LoadIconW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgPrivateExtractIconsA;
    stHook[nIndex].szFunc = "PrivateExtractIconsA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgPrivateExtractIconsW;
    stHook[nIndex].szFunc = "PrivateExtractIconsW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    // Cursor
    stHook[nIndex].pProc = (PROC)pOrgCreateCursor;
    stHook[nIndex].szFunc = "CreateCursor";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLoadCursorA;
    stHook[nIndex].szFunc = "LoadCursorA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLoadCursorW;
    stHook[nIndex].szFunc = "LoadCursorW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLoadCursorFromFileA;
    stHook[nIndex].szFunc = "LoadCursorFromFileA";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLoadCursorFromFileW;
    stHook[nIndex].szFunc = "LoadCursorFromFileW";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDestroyCursor;
    stHook[nIndex].szFunc = "DestroyCursor";
    stHook[nIndex].lpszDllName = _T("user32.dll");
    nIndex++;


    // brush
    stHook[nIndex].pProc = (PROC)pOrgCreateBrushIndirect;
    stHook[nIndex].szFunc = "CreateBrushIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateSolidBrush;
    stHook[nIndex].szFunc = "CreateSolidBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreatePatternBrush;
    stHook[nIndex].szFunc = "CreatePatternBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateDIBPatternBrush;
    stHook[nIndex].szFunc = "CreateDIBPatternBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateDIBPatternBrushPt;
    stHook[nIndex].szFunc = "CreateDIBPatternBrushPt";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateHatchBrush;
    stHook[nIndex].szFunc = "CreateHatchBrush";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // DC creation
    stHook[nIndex].pProc = (PROC)pOrgCreateCompatibleDC;
    stHook[nIndex].szFunc = "CreateCompatibleDC";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateDCA;
    stHook[nIndex].szFunc = "CreateDCA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateDCW;
    stHook[nIndex].szFunc = "CreateDCW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateICA;
    stHook[nIndex].szFunc = "CreateICA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateICW;
    stHook[nIndex].szFunc = "CreateICW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetDC;
    stHook[nIndex].szFunc = "GetDC";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetDCEx;
    stHook[nIndex].szFunc = "GetDCEx";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetWindowDC;
    stHook[nIndex].szFunc = "GetWindowDC";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgReleaseDC;
    stHook[nIndex].szFunc = "ReleaseDC";
    stHook[nIndex].lpszDllName = _T("User32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteDC;
    stHook[nIndex].szFunc = "DeleteDC";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    //Font
    stHook[nIndex].pProc = (PROC)pOrgCreateFontA;
    stHook[nIndex].szFunc = "CreateFontA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFontW;
    stHook[nIndex].szFunc = "CreateFontW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFontIndirectA;
    stHook[nIndex].szFunc = "CreateFontIndirectA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFontIndirectW;
    stHook[nIndex].szFunc = "CreateFontIndirectW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // Meta file
    stHook[nIndex].pProc = (PROC)pOrgCreateMetaFileA;
    stHook[nIndex].szFunc = "CreateMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMetaFileW;
    stHook[nIndex].szFunc = "CreateMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateEnhMetaFileA;
    stHook[nIndex].szFunc = "CreateEnhMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateEnhMetaFileW;
    stHook[nIndex].szFunc = "CreateEnhMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetEnhMetaFileA;
    stHook[nIndex].szFunc = "GetEnhMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetEnhMetaFileW;
    stHook[nIndex].szFunc = "GetEnhMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetMetaFileA;
    stHook[nIndex].szFunc = "GetMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGetMetaFileW;
    stHook[nIndex].szFunc = "GetMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteMetaFile;
    stHook[nIndex].szFunc = "DeleteMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteEnhMetaFile;
    stHook[nIndex].szFunc = "DeleteEnhMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCopyEnhMetaFileA;
    stHook[nIndex].szFunc = "CopyEnhMetaFileA";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCopyEnhMetaFileW;
    stHook[nIndex].szFunc = "CopyEnhMetaFileW";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCloseEnhMetaFile;
    stHook[nIndex].szFunc = "CloseEnhMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCloseMetaFile;
    stHook[nIndex].szFunc = "CloseMetaFile";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    //pen
    stHook[nIndex].pProc = (PROC)pOrgCreatePen;
    stHook[nIndex].szFunc = "CreatePen";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreatePenIndirect;
    stHook[nIndex].szFunc = "CreatePenIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtCreatePen;
    stHook[nIndex].szFunc = "ExtCreatePen";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // rgn
    stHook[nIndex].pProc = (PROC)pOrgPathToRegion;
    stHook[nIndex].szFunc = "PathToRegion";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateEllipticRgn;
    stHook[nIndex].szFunc = "CreateEllipticRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateEllipticRgnIndirect;
    stHook[nIndex].szFunc = "CreateEllipticRgnIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreatePolygonRgn;
    stHook[nIndex].szFunc = "CreatePolygonRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreatePolyPolygonRgn;
    stHook[nIndex].szFunc = "CreatePolyPolygonRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateRectRgn;
    stHook[nIndex].szFunc = "CreateRectRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateRectRgnIndirect;
    stHook[nIndex].szFunc = "CreateRectRgnIndirect";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateRoundRectRgn;
    stHook[nIndex].szFunc = "CreateRoundRectRgn";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgExtCreateRegion;
    stHook[nIndex].szFunc = "ExtCreateRegion";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    // Palette
    stHook[nIndex].pProc = (PROC)pOrgCreateHalftonePalette;
    stHook[nIndex].szFunc = "CreateHalftonePalette";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreatePalette;
    stHook[nIndex].szFunc = "CreatePalette";
    stHook[nIndex].lpszDllName = _T("Gdi32.dll");
    nIndex++;

    HookDynamicLoadedFun( nIndex, stHook );
}

//////////////////////////////////////////////////////////////////////////
// Handle functions
//////////////////////////////////////////////////////////////////////////
HANDLE WINAPI MyCreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,LPCSTR lpName)
{
    HANDLE hHandle = pOrgCreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateEventW( LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,LPCWSTR lpName)
{
    HANDLE hHandle = pOrgCreateEventW( lpEventAttributes, bManualReset, bInitialState, lpName);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateEventExA( LPSECURITY_ATTRIBUTES lpEventAttributes, LPCSTR lpName, DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle = pOrgCreateEventExA( lpEventAttributes,  lpName,  dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateEventExW( LPSECURITY_ATTRIBUTES lpEventAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess )
{
    HANDLE hHandle = pOrgCreateEventExW( lpEventAttributes,  lpName,  dwFlags,  dwDesiredAccess );
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenEventA( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
    HANDLE hHandle = pOrgOpenEventA( dwDesiredAccess,  bInheritHandle,  lpName);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenEventW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName )
{
    HANDLE hHandle = pOrgOpenEventW( dwDesiredAccess,  bInheritHandle,  lpName );
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}

HANDLE WINAPI MyCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner, LPCSTR lpName )
{
    HANDLE hHandle = pOrgCreateMutexA(lpMutexAttributes, bInitialOwner,  lpName );
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCWSTR lpName)
{
    HANDLE hHandle = pOrgCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateMutexExA(LPSECURITY_ATTRIBUTES lpEventAttributes,LPCSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle = pOrgCreateMutexExA(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateMutexExW(LPSECURITY_ATTRIBUTES lpEventAttributes,LPCWSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle = pOrgCreateMutexExW(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenMutexA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName)
{
    HANDLE hHandle = pOrgOpenMutexA(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenMutexW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName)
{
    HANDLE hHandle = pOrgOpenMutexW(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE);
    return hHandle;
}

HANDLE WINAPI MyCreateSemaphoreA( LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,LPCSTR lpName )
{
    HANDLE hHandle = pOrgCreateSemaphoreA( lpSemaphoreAttributes,  lInitialCount,  lMaximumCount, lpName );
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName)
{
    HANDLE hHandle = pOrgCreateSemaphoreW(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateSemaphoreExA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle = pOrgCreateSemaphoreExA(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateSemaphoreExW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle = pOrgCreateSemaphoreExW(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenSemaphoreA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName)
{
    HANDLE hHandle = pOrgOpenSemaphoreA(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenSemaphoreW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPWSTR lpName)
{
    HANDLE hHandle = pOrgOpenSemaphoreW(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}

HANDLE WINAPI MyCreateWaitableTimerA( LPSECURITY_ATTRIBUTES lpTimerAttributes, BOOL bManualReset, LPCSTR lpTimerName)
{
    HANDLE hHandle = pOrgCreateWaitableTimerA( lpTimerAttributes,  bManualReset,  lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateWaitableTimerW(LPSECURITY_ATTRIBUTES lpTimerAttributes,BOOL bManualReset,LPCWSTR lpTimerName)
{
    HANDLE hHandle = pOrgCreateWaitableTimerW(lpTimerAttributes, bManualReset, lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateWaitableTimerExA(LPSECURITY_ATTRIBUTES lpTimerAttributes,LPCSTR lpTimerName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle = pOrgCreateWaitableTimerExA(lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateWaitableTimerExW(LPSECURITY_ATTRIBUTES lpTimerAttributes,LPCWSTR lpTimerName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle = pOrgCreateWaitableTimerExW(lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess); 
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenWaitableTimerA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpTimerName)
{
    HANDLE hHandle = pOrgOpenWaitableTimerA(dwDesiredAccess, bInheritHandle, lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenWaitableTimerW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpTimerName)
{
    HANDLE hHandle = pOrgOpenWaitableTimerW(dwDesiredAccess, bInheritHandle, lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}

// file function
HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
    HANDLE hHandle = pOrgCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
    HANDLE hHandle = pOrgCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateFileTransactedA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile,HANDLE hTransaction,PUSHORT pusMiniVersion,PVOID  lpExtendedParameter)
{
    HANDLE hHandle = pOrgCreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion,  lpExtendedParameter);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateFileTransactedW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile,HANDLE hTransaction,PUSHORT pusMiniVersion,PVOID  lpExtendedParameter )
{
    HANDLE hHandle = pOrgCreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion,  lpExtendedParameter );
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData)
{
    HANDLE hHandle = pOrgFindFirstFileA(lpFileName, lpFindFileData);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData)
{
    HANDLE hHandle = pOrgFindFirstFileW(lpFileName, lpFindFileData); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileExA(LPCSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags)
{
    HANDLE hHandle = pOrgFindFirstFileExA(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileExW(LPCWSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags)
{
    HANDLE hHandle = pOrgFindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileNameTransactedW (LPCWSTR lpFileName,DWORD dwFlags,LPDWORD StringLength,PWCHAR LinkName,HANDLE hTransaction)
{
    HANDLE hHandle = pOrgFindFirstFileNameTransactedW (lpFileName, dwFlags, StringLength, LinkName, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileNameW (LPCWSTR lpFileName,DWORD dwFlags,LPDWORD StringLength,PWCHAR LinkName)
{
    HANDLE hHandle = pOrgFindFirstFileNameW (lpFileName, dwFlags, StringLength, LinkName); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileTransactedA(LPCSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags,HANDLE hTransaction)
{
    HANDLE hHandle = pOrgFindFirstFileTransactedA(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstFileTransactedW(LPCWSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags,HANDLE hTransaction)
{
    HANDLE hHandle = pOrgFindFirstFileTransactedW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstStreamTransactedW(LPCWSTR lpFileName,STREAM_INFO_LEVELS InfoLevel,LPVOID lpFindStreamData,DWORD dwFlags,HANDLE hTransaction)
{
    HANDLE hHandle = pOrgFindFirstStreamTransactedW(lpFileName, InfoLevel, lpFindStreamData, dwFlags, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstStreamW( LPCWSTR lpFileName,STREAM_INFO_LEVELS InfoLevel,LPVOID lpFindStreamData,DWORD dwFlags)
{
    HANDLE hHandle = pOrgFindFirstStreamW( lpFileName, InfoLevel, lpFindStreamData, dwFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
BOOL WINAPI MyFindClose( HANDLE hFindFile)
{
    BOOL bRet  = pOrgFindClose( hFindFile);
    if( bRet )
        RemovCallStack( hFindFile );
    return bRet;
}
HANDLE WINAPI MyOpenFileById(HANDLE hFile,LPFILE_ID_DESCRIPTOR lpFileID,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwFlags)
{
    HANDLE hHandle = pOrgOpenFileById(hFile, lpFileID, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyReOpenFile(HANDLE hOriginalFile,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwFlags)
{
    HANDLE hHandle = pOrgReOpenFile(hOriginalFile, dwDesiredAccess, dwShareMode, dwFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateIoCompletionPort(HANDLE FileHandle,HANDLE ExistingCompletionPort,ULONG_PTR CompletionKey,DWORD NumberOfConcurrentThreads)
{
    HANDLE hHandle = pOrgCreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}

//Authorization function
BOOL   WINAPI MyCreateRestrictedToken(HANDLE ExistingTokenHandle,DWORD Flags,DWORD DisableSidCount,PSID_AND_ATTRIBUTES SidsToDisable,DWORD DeletePrivilegeCount,PLUID_AND_ATTRIBUTES PrivilegesToDelete,DWORD RestrictedSidCount,PSID_AND_ATTRIBUTES SidsToRestrict,PHANDLE NewTokenHandle)
{
    BOOL   bret = pOrgCreateRestrictedToken(ExistingTokenHandle, Flags, DisableSidCount, SidsToDisable, DeletePrivilegeCount, PrivilegesToDelete, RestrictedSidCount, SidsToRestrict, NewTokenHandle);
    if( bret )
        CreateCallStack( *NewTokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI MyDuplicateToken(HANDLE ExistingTokenHandle,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,PHANDLE DuplicateTokenHandle)
{
    BOOL   bret = pOrgDuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle);
    if( bret )
        CreateCallStack( *DuplicateTokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI MyDuplicateTokenEx(HANDLE hExistingToken,DWORD dwDesiredAccess,LPSECURITY_ATTRIBUTES lpTokenAttributes,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,TOKEN_TYPE TokenType,PHANDLE phNewToken)
{
    BOOL   bret = pOrgDuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken);
    if( bret )
        CreateCallStack( *phNewToken, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI MyOpenProcessToken(HANDLE ProcessHandle,DWORD DesiredAccess,PHANDLE TokenHandle)
{
    BOOL   bret = pOrgOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
    if( bret )
        CreateCallStack( *TokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI MyOpenThreadToken(HANDLE ThreadHandle,DWORD DesiredAccess,BOOL OpenAsSelf,PHANDLE TokenHandle)
{
    BOOL   bret = pOrgOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle); 
    if( bret )
        CreateCallStack( *TokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}

//Directory management
HANDLE WINAPI MyFindFirstChangeNotificationA(LPCSTR lpPathName,BOOL bWatchSubtree,DWORD dwNotifyFilter)
{
    HANDLE hHandle = pOrgFindFirstChangeNotificationA(lpPathName, bWatchSubtree, dwNotifyFilter);
    CreateCallStack( hHandle, TYPE_CHANGE_NOFICATION_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyFindFirstChangeNotificationW(LPCWSTR lpPathName,BOOL bWatchSubtree,DWORD dwNotifyFilter)
{
    HANDLE hHandle = pOrgFindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter); 
    CreateCallStack( hHandle, TYPE_CHANGE_NOFICATION_HANDLE );
    return hHandle;
}
BOOL   WINAPI MyFindCloseChangeNotification(HANDLE hChangeHandle)
{
    BOOL   bRet = pOrgFindCloseChangeNotification(hChangeHandle); 
    if( bRet )
        RemovCallStack( hChangeHandle );
    return bRet;

}

// File mapping
HANDLE WINAPI MyCreateMemoryResourceNotification( MEMORY_RESOURCE_NOTIFICATION_TYPE NotificationType )
{
    HANDLE hHandle = pOrgCreateMemoryResourceNotification( NotificationType );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateFileMappingA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName )
{
    HANDLE hHandle = pOrgCreateFileMappingA( hFile,  lpFileMappingAttributes,  flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateFileMappingW( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName )
{
    HANDLE hHandle = pOrgCreateFileMappingW( hFile, lpFileMappingAttributes, flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateFileMappingNumaA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName, DWORD nndPreferred )
{
    HANDLE hHandle = pOrgCreateFileMappingNumaA( hFile,  lpFileMappingAttributes,  flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName,  nndPreferred );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateFileMappingNumaW( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName, DWORD nndPreferred )
{
    HANDLE hHandle = pOrgCreateFileMappingNumaW( hFile,  lpFileMappingAttributes,  flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName,  nndPreferred );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenFileMappingA( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName )
{
    HANDLE hHandle = pOrgOpenFileMappingA( dwDesiredAccess,  bInheritHandle,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenFileMappingW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName )
{
    HANDLE hHandle = pOrgOpenFileMappingW( dwDesiredAccess,  bInheritHandle,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}

//Memory
HANDLE WINAPI MyHeapCreate( DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize )
{
    HANDLE hHandle = pOrgHeapCreate( flOptions,  dwInitialSize,  dwMaximumSize );
    CreateCallStack( hHandle, TYPE_MEMORY_HANDLE );
    return hHandle;
}
BOOL   WINAPI MyHeapDestroy(HANDLE hHeap )
{
    BOOL   bRet = pOrgHeapDestroy(hHeap );
    if( bRet )
        RemovCallStack( hHeap );
    return bRet;

}

//Process and thread
BOOL   WINAPI MyCreateProcessA( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    BOOL   bret = pOrgCreateProcessA( lpApplicationName,  lpCommandLine,  lpProcessAttributes,  lpThreadAttributes,  bInheritHandles,  dwCreationFlags,  lpEnvironment,  lpCurrentDirectory,  lpStartupInfo,  lpProcessInformation );
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI MyCreateProcessW( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    BOOL   bret = pOrgCreateProcessW( lpApplicationName,  lpCommandLine,  lpProcessAttributes,  lpThreadAttributes,  bInheritHandles,  dwCreationFlags,  lpEnvironment,  lpCurrentDirectory,  lpStartupInfo,  lpProcessInformation );
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI MyCreateProcessAsUserA(HANDLE hToken,LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret = pOrgCreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI MyCreateProcessAsUserW(HANDLE hToken,LPWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret = pOrgCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI MyCreateProcessWithLogonW(LPCWSTR lpUsername,LPCWSTR lpDomain,LPCWSTR lpPassword,DWORD dwLogonFlags,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret = pOrgCreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI MyCreateProcessWithTokenW(HANDLE hToken,DWORD dwLogonFlags,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret = pOrgCreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation); 
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
HANDLE WINAPI MyOpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId )
{
    HANDLE hHandle = pOrgOpenProcess( dwDesiredAccess,  bInheritHandle,  dwProcessId );
    CreateCallStack( hHandle, TYPE_PROCESS_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateThread( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    HANDLE hHandle = pOrgCreateThread( lpThreadAttributes,  dwStackSize,  lpStartAddress,  lpParameter,  dwCreationFlags,  lpThreadId );
    CreateCallStack( hHandle, TYPE_THREAD_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateRemoteThread( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    HANDLE hHandle = pOrgCreateRemoteThread( hProcess,  lpThreadAttributes,  dwStackSize,  lpStartAddress,  lpParameter,  dwCreationFlags,  lpThreadId );
    CreateCallStack( hHandle, TYPE_THREAD_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyOpenThread( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId )
{
    HANDLE hHandle = pOrgOpenThread( dwDesiredAccess,  bInheritHandle,  dwThreadId );
    CreateCallStack( hHandle, TYPE_THREAD_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateJobObjectA( LPSECURITY_ATTRIBUTES lpJobAttributes, LPCSTR lpName )
{
    HANDLE hHandle = pOrgCreateJobObjectA( lpJobAttributes, lpName );
    CreateCallStack( hHandle, TYPE_JOB_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateJobObjectW( LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName )
{
    HANDLE hHandle = pOrgCreateJobObjectW( lpJobAttributes, lpName );
    CreateCallStack( hHandle, TYPE_JOB_HANDLE );
    return hHandle;
}

// Mail slot
HANDLE WINAPI MyCreateMailslotA( LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle = pOrgCreateMailslotA( lpName,  nMaxMessageSize,  lReadTimeout,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_MAIL_SLOT_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateMailslotW( LPCWSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle = pOrgCreateMailslotW( lpName,  nMaxMessageSize,  lReadTimeout,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_MAIL_SLOT_HANDLE );
    return hHandle;
}

// pipe
BOOL   WINAPI MyCreatePipe( PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize )
{
    BOOL   bret = pOrgCreatePipe( hReadPipe,  hWritePipe,  lpPipeAttributes,  nSize ); 
    if( bret )
    {
        CreateCallStack( *hReadPipe, TYPE_PIPE_HANDLE );
        CreateCallStack( *hWritePipe, TYPE_PIPE_HANDLE );
    }
    return bret;
}
HANDLE WINAPI MyCreateNamedPipeA( LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle = pOrgCreateNamedPipeA( lpName,  dwOpenMode,  dwPipeMode,  nMaxInstances,  nOutBufferSize,  nInBufferSize,  nDefaultTimeOut,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_PIPE_HANDLE );
    return hHandle;
}
HANDLE WINAPI MyCreateNamedPipeW( LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle = pOrgCreateNamedPipeW( lpName, dwOpenMode,  dwPipeMode,  nMaxInstances,  nOutBufferSize,  nInBufferSize,  nDefaultTimeOut,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_PIPE_HANDLE );
    return hHandle;
}

//Registry
LSTATUS WINAPI MyRegCreateKeyExA( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition )
{
    LSTATUS hHandle = pOrgRegCreateKeyExA( hKey, lpSubKey,  Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegCreateKeyExW ( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition )
{
    LSTATUS hHandle = pOrgRegCreateKeyExW ( hKey,  lpSubKey,  Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegCreateKeyTransactedA( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle = pOrgRegCreateKeyTransactedA( hKey,  lpSubKey,  Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition, hTransaction,   pExtendedParemeter );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegCreateKeyTransactedW( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle = pOrgRegCreateKeyTransactedW( hKey, lpSubKey, Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition,  hTransaction,   pExtendedParemeter ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenCurrentUser( REGSAM samDesired, PHKEY phkResult )
{
    LSTATUS hHandle = pOrgRegOpenCurrentUser( samDesired,  phkResult ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenKeyA ( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle = pOrgRegOpenKeyA ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenKeyW ( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle = pOrgRegOpenKeyW ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenKeyExA ( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult )
{
    LSTATUS hHandle = pOrgRegOpenKeyExA ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenKeyExW ( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult )
{
    LSTATUS hHandle = pOrgRegOpenKeyExW ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenKeyTransactedA ( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle = pOrgRegOpenKeyTransactedA ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult,  hTransaction,   pExtendedParemeter );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenKeyTransactedW ( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle = pOrgRegOpenKeyTransactedW ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult,  hTransaction,   pExtendedParemeter );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegOpenUserClassesRoot( HANDLE hToken, DWORD dwOptions, REGSAM samDesired, PHKEY  phkResult )
{
    LSTATUS hHandle = pOrgRegOpenUserClassesRoot( hToken,  dwOptions,  samDesired,   phkResult ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegCreateKeyA ( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle = pOrgRegCreateKeyA ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegCreateKeyW ( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle = pOrgRegCreateKeyW ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI MyRegCloseKey ( HKEY hKey )
{
    LSTATUS bRet = pOrgRegCloseKey ( hKey ); 
    if( bRet )
        RemovCallStack( hKey );
    return bRet;
}

////////////////////////////////start - v3 additions//////////////////////////////////////////////////
// Timers
HANDLE WINAPI MyCreateTimerQueue(void)
{
    HANDLE hHandle = pOrgCreateTimerQueue();
    if( hHandle )
        CreateCallStack( hHandle, TYPE_TIMER_QUEUE );
    return hHandle;
}

BOOL   WINAPI MyCreateTimerQueueTimer(PHANDLE phNewTimer,HANDLE TimerQueue,WAITORTIMERCALLBACK Callback,PVOID Parameter,DWORD DueTime,DWORD Period,ULONG Flags)
{
    BOOL bRet = pOrgCreateTimerQueueTimer(phNewTimer,TimerQueue,Callback,Parameter,DueTime,Period,Flags);
    if( bRet && phNewTimer && *phNewTimer )
        CreateCallStack( *phNewTimer, TYPE_TIMER_QUEUE );
    return bRet;
}

BOOL   WINAPI MyDeleteTimerQueueTimer(HANDLE TimerQueue,HANDLE Timer,HANDLE CompletionEvent)
{
    BOOL bRet = pOrgDeleteTimerQueueTimer(TimerQueue,Timer,CompletionEvent);
    if( bRet )
        RemovCallStack( Timer );
    return bRet;
}

BOOL   WINAPI MyDeleteTimerQueueEx(HANDLE TimerQueue,HANDLE CompletionEvent)
{
    BOOL bRet = pOrgDeleteTimerQueueEx(TimerQueue,CompletionEvent);
    if( bRet )
        RemovCallStack( TimerQueue );
    return bRet;
}

BOOL WINAPI MyDeleteTimerQueue(HANDLE TimerQueue)
{
    BOOL bRet = pOrgDeleteTimerQueue(TimerQueue);
    if( bRet )
        RemovCallStack( TimerQueue );
    return bRet;
}

//Critical section
void WINAPI MyInitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pOrgInitializeCriticalSection( lpCriticalSection );
    CreateCallStack( lpCriticalSection, TYPE_CRITICAL_SECTION_HANDLE );
}
BOOL WINAPI MyInitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount,DWORD Flags)
{
    BOOL bRet = pOrgInitializeCriticalSectionEx(lpCriticalSection, dwSpinCount, Flags);
    if( bRet )
        CreateCallStack( lpCriticalSection, TYPE_CRITICAL_SECTION_HANDLE );
    return bRet;
}

BOOL WINAPI MyInitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount)
{
    BOOL bRet = pOrgInitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
    if( bRet )
        CreateCallStack( lpCriticalSection, TYPE_CRITICAL_SECTION_HANDLE );
    return bRet;
}
void WINAPI MyDeleteCriticalSection( LPCRITICAL_SECTION lpCriticalSection)
{
    pOrgDeleteCriticalSection(lpCriticalSection);
    RemovCallStack( lpCriticalSection );
    
}

////////////////////////////////end - v3 additions//////////////////////////////////////////////////

BOOL   WINAPI MyDuplicateHandle(HANDLE hSourceProcessHandle,HANDLE hSourceHandle,HANDLE hTargetProcessHandle,LPHANDLE lpTargetHandle,DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwOptions)
{
    BOOL   bret = pOrgDuplicateHandle(hSourceProcessHandle,hSourceHandle,hTargetProcessHandle, lpTargetHandle,dwDesiredAccess,bInheritHandle,dwOptions);
    
    if(DUPLICATE_CLOSE_SOURCE&dwOptions)
    {
        RemovCallStack( hSourceHandle );
    }
    
    if( bret )
        CreateCallStack( *lpTargetHandle, TYPE_UNKNOWN );
    return bret;
}

BOOL   WINAPI MyCloseHandle( HANDLE hObject )
{
    BOOL   bRet = pOrgCloseHandle( hObject );
    if( bRet )
        RemovCallStack( hObject );
    return bRet;

}

const int HANDLE_FUNC_COUNT = 108;
void HookHandleAlloc()
{
    HMODULE hKernel32Module = LoadLibrary( "Kernel32.dll" );
    HMODULE hAdvapi32Module = LoadLibrary( "Advapi32.dll" );
    pOrgCreateEventA  = (CreateEventADef)GetProcAddress( hKernel32Module, "CreateEventA" );
    pOrgCreateEventW = (CreateEventWDef)GetProcAddress( hKernel32Module, "CreateEventW" );
    pOrgCreateEventExA = (CreateEventExADef)GetProcAddress( hKernel32Module, "CreateEventExA" );
    pOrgCreateEventExW = (CreateEventExWDef)GetProcAddress( hKernel32Module, "CreateEventExW" );
    pOrgOpenEventA = (OpenEventADef)GetProcAddress( hKernel32Module, "OpenEventA" );
    pOrgOpenEventW = (OpenEventWDef)GetProcAddress( hKernel32Module, "OpenEventW" );
    pOrgCreateMutexA = (CreateMutexADef)GetProcAddress( hKernel32Module, "CreateMutexA" );
    pOrgCreateMutexW = (CreateMutexWDef)GetProcAddress( hKernel32Module, "CreateMutexW" );
    pOrgCreateMutexExA = (CreateMutexExADef)GetProcAddress( hKernel32Module, "CreateMutexExA" );
    pOrgCreateMutexExW = (CreateMutexExWDef)GetProcAddress( hKernel32Module, "CreateMutexExW" );
    pOrgOpenMutexA = (OpenMutexADef)GetProcAddress( hKernel32Module, "OpenMutexA" );
    pOrgOpenMutexW = (OpenMutexWDef)GetProcAddress( hKernel32Module, "OpenMutexW" );
    pOrgCreateSemaphoreA = (CreateSemaphoreADef)GetProcAddress( hKernel32Module, "CreateSemaphoreA" );
    pOrgCreateSemaphoreW = (CreateSemaphoreWDef)GetProcAddress( hKernel32Module, "CreateSemaphoreW" );
    pOrgCreateSemaphoreExA = (CreateSemaphoreExADef)GetProcAddress( hKernel32Module, "CreateSemaphoreExA" );
    pOrgCreateSemaphoreExW = (CreateSemaphoreExWDef)GetProcAddress( hKernel32Module, "CreateSemaphoreExW" );
    pOrgOpenSemaphoreA = (OpenSemaphoreADef)GetProcAddress( hKernel32Module, "OpenSemaphoreA" );
    pOrgOpenSemaphoreW = (OpenSemaphoreWDef)GetProcAddress( hKernel32Module, "OpenSemaphoreW" );
    pOrgCreateWaitableTimerA = (CreateWaitableTimerADef)GetProcAddress( hKernel32Module, "CreateWaitableTimerA" );
    pOrgCreateWaitableTimerW = (CreateWaitableTimerWDef)GetProcAddress( hKernel32Module, "CreateWaitableTimerW" );
    pOrgCreateWaitableTimerExA = (CreateWaitableTimerExADef)GetProcAddress( hKernel32Module, "CreateWaitableTimerExA" );
    pOrgCreateWaitableTimerExW = (CreateWaitableTimerExWDef)GetProcAddress( hKernel32Module, "CreateWaitableTimerExW" );
    pOrgOpenWaitableTimerA = (OpenWaitableTimerADef)GetProcAddress( hKernel32Module, "OpenWaitableTimerA" );
    pOrgOpenWaitableTimerW = (OpenWaitableTimerWDef)GetProcAddress( hKernel32Module, "OpenWaitableTimerW" );
    pOrgCreateFileA = (CreateFileADef)GetProcAddress( hKernel32Module, "CreateFileA" );
    pOrgCreateFileW = (CreateFileWDef)GetProcAddress( hKernel32Module, "CreateFileW" );
    pOrgCreateFileTransactedA = (CreateFileTransactedADef)GetProcAddress( hKernel32Module, "CreateFileTransactedA" );
    pOrgCreateFileTransactedW = (CreateFileTransactedWDef)GetProcAddress( hKernel32Module, "CreateFileTransactedW" );
    pOrgFindFirstFileA = (FindFirstFileADef)GetProcAddress( hKernel32Module, "FindFirstFileA" );
    pOrgFindFirstFileW = (FindFirstFileWDef)GetProcAddress( hKernel32Module, "FindFirstFileW" );
    pOrgFindFirstFileExA = (FindFirstFileExADef)GetProcAddress( hKernel32Module, "FindFirstFileExA" );
    pOrgFindFirstFileExW = (FindFirstFileExWDef)GetProcAddress( hKernel32Module, "FindFirstFileExW" );
    pOrgFindFirstFileNameTransactedW  = (FindFirstFileNameTransactedWDef)GetProcAddress( hKernel32Module, "FindFirstFileExW" );
    pOrgFindFirstFileNameW = (FindFirstFileNameWDef)GetProcAddress( hKernel32Module, "FindFirstFileNameW" );
    pOrgFindFirstFileTransactedA = (FindFirstFileTransactedADef)GetProcAddress( hKernel32Module, "FindFirstFileTransactedA" );
    pOrgFindFirstFileTransactedW = (FindFirstFileTransactedWDef)GetProcAddress( hKernel32Module, "FindFirstFileTransactedW" );
    pOrgFindFirstStreamTransactedW = (FindFirstStreamTransactedWDef)GetProcAddress( hKernel32Module, "FindFirstStreamTransactedW" );
    pOrgFindFirstStreamW = (FindFirstStreamWDef)GetProcAddress( hKernel32Module, "FindFirstStreamW" );
    pOrgFindClose = (FindCloseDef)GetProcAddress( hKernel32Module, "FindClose" );
    pOrgOpenFileById = (OpenFileByIdDef)GetProcAddress( hKernel32Module, "OpenFileById" );
    pOrgReOpenFile = (ReOpenFileDef)GetProcAddress( hKernel32Module, "ReOpenFile" );
    pOrgCreateIoCompletionPort = (CreateIoCompletionPortDef)GetProcAddress( hKernel32Module, "CreateIoCompletionPort" );
    pOrgCreateRestrictedToken = (CreateRestrictedTokenDef)GetProcAddress( hAdvapi32Module, "CreateRestrictedToken" );
    pOrgDuplicateToken = (DuplicateTokenDef)GetProcAddress( hAdvapi32Module, "DuplicateToken" );
    pOrgDuplicateTokenEx = (DuplicateTokenExDef)GetProcAddress( hAdvapi32Module, "DuplicateTokenEx" );
    pOrgOpenProcessToken = (OpenProcessTokenDef)GetProcAddress( hAdvapi32Module, "OpenProcessToken" );
    pOrgOpenThreadToken = (OpenThreadTokenDef)GetProcAddress( hAdvapi32Module, "OpenThreadToken" );
    pOrgFindFirstChangeNotificationA = (FindFirstChangeNotificationADef)GetProcAddress( hKernel32Module, "FindFirstChangeNotificationA" );
    pOrgFindFirstChangeNotificationW = (FindFirstChangeNotificationWDef)GetProcAddress( hKernel32Module, "FindFirstChangeNotificationW" );
    pOrgFindCloseChangeNotification = (FindCloseChangeNotificationDef)GetProcAddress( hKernel32Module, "FindCloseChangeNotification" );
    pOrgCreateMemoryResourceNotification = (CreateMemoryResourceNotificationDef)GetProcAddress( hKernel32Module, "CreateMemoryResourceNotification" );
    pOrgCreateFileMappingA = (CreateFileMappingADef)GetProcAddress( hKernel32Module, "CreateFileMappingA" );
    pOrgCreateFileMappingW = (CreateFileMappingWDef)GetProcAddress( hKernel32Module, "CreateFileMappingW" );
    pOrgCreateFileMappingNumaA = (CreateFileMappingNumaADef)GetProcAddress( hKernel32Module, "CreateFileMappingNumaA" );
    pOrgCreateFileMappingNumaW = (CreateFileMappingNumaWDef)GetProcAddress( hKernel32Module, "CreateFileMappingNumaW" );
    pOrgOpenFileMappingA = (OpenFileMappingADef)GetProcAddress( hKernel32Module, "OpenFileMappingA" );
    pOrgOpenFileMappingW = (OpenFileMappingWDef)GetProcAddress( hKernel32Module, "OpenFileMappingW" );
    pOrgHeapCreate = (HeapCreateDef)GetProcAddress( hKernel32Module, "HeapCreate" );
    pOrgHeapDestroy = (HeapDestroyDef)GetProcAddress( hKernel32Module, "HeapDestroy" );
    pOrgGlobalAlloc = (GlobalAllocDef)GetProcAddress( hKernel32Module, "GlobalAlloc" );
    pOrgGlobalReAlloc = (GlobalReAllocDef)GetProcAddress( hKernel32Module, "GlobalReAlloc" );
    pOrgGlobalFree = (GlobalFreeDef)GetProcAddress( hKernel32Module, "GlobalFree" );
    pOrgLocalAlloc = (LocalAllocDef)GetProcAddress( hKernel32Module, "LocalAlloc" );
    pOrgLocalReAlloc = (LocalReAllocDef)GetProcAddress( hKernel32Module, "LocalReAlloc" );
    pOrgLocalFree = (LocalFreeDef)GetProcAddress( hKernel32Module, "LocalFree" );
    pOrgCreateProcessA = (CreateProcessADef)GetProcAddress( hKernel32Module, "CreateProcessA" );
    pOrgCreateProcessW = (CreateProcessWDef)GetProcAddress( hKernel32Module, "CreateProcessW" );
    pOrgCreateProcessAsUserA = (CreateProcessAsUserADef)GetProcAddress( hAdvapi32Module, "CreateProcessAsUserA" );
    pOrgCreateProcessAsUserW = (CreateProcessAsUserWDef)GetProcAddress( hAdvapi32Module, "CreateProcessAsUserW" );
    pOrgCreateProcessWithLogonW = (CreateProcessWithLogonWDef)GetProcAddress( hAdvapi32Module, "CreateProcessWithLogonW" );
    pOrgCreateProcessWithTokenW = (CreateProcessWithTokenWDef)GetProcAddress( hAdvapi32Module, "CreateProcessWithTokenW" );
    pOrgOpenProcess = (OpenProcessDef)GetProcAddress( hKernel32Module, "OpenProcess" );
    pOrgCreateThread = (CreateThreadDef)GetProcAddress( hKernel32Module, "CreateThread" );
    pOrgCreateRemoteThread = (CreateRemoteThreadDef)GetProcAddress( hKernel32Module, "CreateRemoteThread" );
    pOrgOpenThread = (OpenThreadDef)GetProcAddress( hKernel32Module, "OpenThread" );
    pOrgCreateJobObjectA = (CreateJobObjectADef)GetProcAddress( hKernel32Module, "CreateJobObjectA" );
    pOrgCreateJobObjectW = (CreateJobObjectWDef)GetProcAddress( hKernel32Module, "CreateJobObjectW" );
    pOrgCreateMailslotA = (CreateMailslotADef)GetProcAddress( hKernel32Module, "CreateMailslotA" );
    pOrgCreateMailslotW = (CreateMailslotWDef)GetProcAddress( hKernel32Module, "CreateMailslotW" );
    pOrgCreatePipe = (CreatePipeDef)GetProcAddress( hKernel32Module, "CreatePipe" );
    pOrgCreateNamedPipeA = (CreateNamedPipeADef)GetProcAddress( hKernel32Module, "CreateNamedPipeA" );
    pOrgCreateNamedPipeW = (CreateNamedPipeWDef)GetProcAddress( hKernel32Module, "CreateNamedPipeW" );
    pOrgRegCreateKeyExA = (RegCreateKeyExADef)GetProcAddress( hAdvapi32Module, "RegCreateKeyExA" );
    pOrgRegCreateKeyExW  = (RegCreateKeyExWDef)GetProcAddress( hAdvapi32Module, "RegCreateKeyExW" );
    pOrgRegCreateKeyTransactedA = (RegCreateKeyTransactedADef)GetProcAddress( hKernel32Module, "RegCreateKeyTransactedA" );
    pOrgRegCreateKeyTransactedW = (RegCreateKeyTransactedWDef)GetProcAddress( hKernel32Module, "RegCreateKeyTransactedW" );
    pOrgRegOpenCurrentUser = (RegOpenCurrentUserDef)GetProcAddress( hKernel32Module, "RegOpenCurrentUser" );
    pOrgRegOpenKeyA = (RegOpenKeyADef)GetProcAddress( hKernel32Module, "RegOpenKeyA" );
    pOrgRegOpenKeyW = (RegOpenKeyWDef)GetProcAddress( hKernel32Module, "RegOpenKeyW" );
    pOrgRegOpenKeyExA = (RegOpenKeyExADef)GetProcAddress( hKernel32Module, "RegOpenKeyExA" );
    pOrgRegOpenKeyExW = (RegOpenKeyExWDef)GetProcAddress( hKernel32Module, "RegOpenKeyExW" );
    pOrgRegOpenKeyTransactedA = (RegOpenKeyTransactedADef)GetProcAddress( hKernel32Module, "RegOpenKeyTransactedA" );
    pOrgRegOpenKeyTransactedW = (RegOpenKeyTransactedWDef)GetProcAddress( hKernel32Module, "RegOpenKeyTransactedW" );
    pOrgRegOpenUserClassesRoot = (RegOpenUserClassesRootDef)GetProcAddress( hKernel32Module, "RegOpenUserClassesRoot" );
    pOrgRegCreateKeyA = (RegCreateKeyADef)GetProcAddress( hKernel32Module, "RegCreateKeyA" );
    pOrgRegCreateKeyW = (RegCreateKeyWDef)GetProcAddress( hKernel32Module, "RegCreateKeyW" );
    pOrgRegCloseKey = (RegCloseKeyDef)GetProcAddress( hKernel32Module, "RegCloseKey" );
    pOrgDuplicateHandle = (DuplicateHandleDef)GetProcAddress( hKernel32Module, "DuplicateHandle" );
    pOrgCloseHandle = (CloseHandleDef)GetProcAddress( hKernel32Module, "CloseHandle" );

    ////////////////////////////////v3 additions//////////////////////////////////////////////////
    // Timers
    pOrgCreateTimerQueue         = (CreateTimerQueueDef)GetProcAddress( hKernel32Module, "CreateTimerQueue" );
    pOrgCreateTimerQueueTimer    = (CreateTimerQueueTimerDef)GetProcAddress( hKernel32Module, "CreateTimerQueueTimer" );
    pOrgDeleteTimerQueueTimer    = (DeleteTimerQueueTimerDef)GetProcAddress( hKernel32Module, "DeleteTimerQueueTimer" );
    pOrgDeleteTimerQueueEx       = (DeleteTimerQueueExDef)GetProcAddress( hKernel32Module, "DeleteTimerQueueEx" );
    pOrgDeleteTimerQueue         = (DeleteTimerQueueDef)GetProcAddress( hKernel32Module, "DeleteTimerQueue" );

    pOrgInitializeCriticalSection               = (InitializeCriticalSectionDef)GetProcAddress( hKernel32Module, "InitializeCriticalSection" );
    pOrgInitializeCriticalSectionEx             = (InitializeCriticalSectionExDef)GetProcAddress( hKernel32Module, "InitializeCriticalSectionEx" );
    pOrgInitializeCriticalSectionAndSpinCount   = (InitializeCriticalSectionAndSpinCountDef)GetProcAddress( hKernel32Module, "InitializeCriticalSectionAndSpinCount" );
    pOrgDeleteCriticalSection                   = (DeleteCriticalSectionDef)GetProcAddress( hKernel32Module, "DeleteCriticalSection" );

    ////////////////////////////////v3 additions//////////////////////////////////////////////////
    HOOKFUNCDESC stHook[HANDLE_FUNC_COUNT] = {0};
    int nIndex = 0;
    stHook[nIndex].pProc = (PROC)MyCreateEventA;
    stHook[nIndex].szFunc = "CreateEventA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateEventW;
    stHook[nIndex].szFunc = "CreateEventW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateEventExA;
    stHook[nIndex].szFunc = "CreateEventExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateEventExW;
    stHook[nIndex].szFunc = "CreateEventExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenEventA;
    stHook[nIndex].szFunc = "OpenEventA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenEventW;
    stHook[nIndex].szFunc = "OpenEventW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMutexA;
    stHook[nIndex].szFunc = "CreateMutexA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMutexW;
    stHook[nIndex].szFunc = "CreateMutexW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMutexExA;
    stHook[nIndex].szFunc = "CreateMutexExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMutexExW;
    stHook[nIndex].szFunc = "CreateMutexExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenMutexA;
    stHook[nIndex].szFunc = "OpenMutexA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenMutexW;
    stHook[nIndex].szFunc = "OpenMutexW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateSemaphoreA;
    stHook[nIndex].szFunc = "CreateSemaphoreA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateSemaphoreW;
    stHook[nIndex].szFunc = "CreateSemaphoreW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateSemaphoreExA;
    stHook[nIndex].szFunc = "CreateSemaphoreExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateSemaphoreExW;
    stHook[nIndex].szFunc = "CreateSemaphoreExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenSemaphoreA;
    stHook[nIndex].szFunc = "OpenSemaphoreA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenSemaphoreW;
    stHook[nIndex].szFunc = "OpenSemaphoreW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateWaitableTimerA;
    stHook[nIndex].szFunc = "CreateWaitableTimerA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateWaitableTimerW;
    stHook[nIndex].szFunc = "CreateWaitableTimerW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateWaitableTimerExA;
    stHook[nIndex].szFunc = "CreateWaitableTimerExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateWaitableTimerExW;
    stHook[nIndex].szFunc = "CreateWaitableTimerExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenWaitableTimerA;
    stHook[nIndex].szFunc = "OpenWaitableTimerA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenWaitableTimerW;
    stHook[nIndex].szFunc = "OpenWaitableTimerW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileA;
    stHook[nIndex].szFunc = "CreateFileA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileW;
    stHook[nIndex].szFunc = "CreateFileW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileTransactedA;
    stHook[nIndex].szFunc = "CreateFileTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileTransactedW;
    stHook[nIndex].szFunc = "CreateFileTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileA;
    stHook[nIndex].szFunc = "FindFirstFileA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileW;
    stHook[nIndex].szFunc = "FindFirstFileW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileExA;
    stHook[nIndex].szFunc = "FindFirstFileExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileExW;
    stHook[nIndex].szFunc = "FindFirstFileExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileNameTransactedW ;
    stHook[nIndex].szFunc = "FindFirstFileNameTransactedW ";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileNameW;
    stHook[nIndex].szFunc = "FindFirstFileNameW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileTransactedA;
    stHook[nIndex].szFunc = "FindFirstFileTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstFileTransactedW;
    stHook[nIndex].szFunc = "FindFirstFileTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstStreamTransactedW;
    stHook[nIndex].szFunc = "FindFirstStreamTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstStreamW;
    stHook[nIndex].szFunc = "FindFirstStreamW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindClose;
    stHook[nIndex].szFunc = "FindClose";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenFileById;
    stHook[nIndex].szFunc = "OpenFileById";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyReOpenFile;
    stHook[nIndex].szFunc = "ReOpenFile";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateIoCompletionPort;
    stHook[nIndex].szFunc = "CreateIoCompletionPort";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateRestrictedToken;
    stHook[nIndex].szFunc = "CreateRestrictedToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDuplicateToken;
    stHook[nIndex].szFunc = "DuplicateToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDuplicateTokenEx;
    stHook[nIndex].szFunc = "DuplicateTokenEx";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenProcessToken;
    stHook[nIndex].szFunc = "OpenProcessToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenThreadToken;
    stHook[nIndex].szFunc = "OpenThreadToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstChangeNotificationA;
    stHook[nIndex].szFunc = "FindFirstChangeNotificationA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindFirstChangeNotificationW;
    stHook[nIndex].szFunc = "FindFirstChangeNotificationW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyFindCloseChangeNotification;
    stHook[nIndex].szFunc = "FindCloseChangeNotification";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMemoryResourceNotification;
    stHook[nIndex].szFunc = "CreateMemoryResourceNotification";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileMappingA;
    stHook[nIndex].szFunc = "CreateFileMappingA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileMappingW;
    stHook[nIndex].szFunc = "CreateFileMappingW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileMappingNumaA;
    stHook[nIndex].szFunc = "CreateFileMappingNumaA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateFileMappingNumaW;
    stHook[nIndex].szFunc = "CreateFileMappingNumaW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenFileMappingA;
    stHook[nIndex].szFunc = "OpenFileMappingA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenFileMappingW;
    stHook[nIndex].szFunc = "OpenFileMappingW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyHeapCreate;
    stHook[nIndex].szFunc = "HeapCreate";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyHeapDestroy;
    stHook[nIndex].szFunc = "HeapDestroy";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGlobalAlloc;
    stHook[nIndex].szFunc = "GlobalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGlobalReAlloc;
    stHook[nIndex].szFunc = "GlobalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyGlobalFree;
    stHook[nIndex].szFunc = "GlobalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLocalAlloc;
    stHook[nIndex].szFunc = "LocalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLocalReAlloc;
    stHook[nIndex].szFunc = "LocalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyLocalFree;
    stHook[nIndex].szFunc = "LocalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateProcessA;
    stHook[nIndex].szFunc = "CreateProcessA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateProcessW;
    stHook[nIndex].szFunc = "CreateProcessW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateProcessAsUserA;
    stHook[nIndex].szFunc = "CreateProcessAsUserA";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateProcessAsUserW;
    stHook[nIndex].szFunc = "CreateProcessAsUserW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateProcessWithLogonW;
    stHook[nIndex].szFunc = "CreateProcessWithLogonW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateProcessWithTokenW;
    stHook[nIndex].szFunc = "CreateProcessWithTokenW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenProcess;
    stHook[nIndex].szFunc = "OpenProcess";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateThread;
    stHook[nIndex].szFunc = "CreateThread";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateRemoteThread;
    stHook[nIndex].szFunc = "CreateRemoteThread";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyOpenThread;
    stHook[nIndex].szFunc = "OpenThread";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateJobObjectA;
    stHook[nIndex].szFunc = "CreateJobObjectA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateJobObjectW;
    stHook[nIndex].szFunc = "CreateJobObjectW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMailslotA;
    stHook[nIndex].szFunc = "CreateMailslotA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateMailslotW;
    stHook[nIndex].szFunc = "CreateMailslotW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreatePipe;
    stHook[nIndex].szFunc = "CreatePipe";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateNamedPipeA;
    stHook[nIndex].szFunc = "CreateNamedPipeA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateNamedPipeW;
    stHook[nIndex].szFunc = "CreateNamedPipeW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegCreateKeyExA;
    stHook[nIndex].szFunc = "RegCreateKeyExA";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegCreateKeyExW ;
    stHook[nIndex].szFunc = "RegCreateKeyExW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegCreateKeyTransactedA;
    stHook[nIndex].szFunc = "RegCreateKeyTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegCreateKeyTransactedW;
    stHook[nIndex].szFunc = "RegCreateKeyTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenCurrentUser;
    stHook[nIndex].szFunc = "RegOpenCurrentUser";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenKeyA;
    stHook[nIndex].szFunc = "RegOpenKeyA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenKeyW;
    stHook[nIndex].szFunc = "RegOpenKeyW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenKeyExA;
    stHook[nIndex].szFunc = "RegOpenKeyExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenKeyExW;
    stHook[nIndex].szFunc = "RegOpenKeyExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenKeyTransactedA;
    stHook[nIndex].szFunc = "RegOpenKeyTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenKeyTransactedW;
    stHook[nIndex].szFunc = "RegOpenKeyTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegOpenUserClassesRoot;
    stHook[nIndex].szFunc = "RegOpenUserClassesRoot";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegCreateKeyA;
    stHook[nIndex].szFunc = "RegCreateKeyA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegCreateKeyW;
    stHook[nIndex].szFunc = "RegCreateKeyW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyRegCloseKey;
    stHook[nIndex].szFunc = "RegCloseKey";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDuplicateHandle;
    stHook[nIndex].szFunc = "DuplicateHandle";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCloseHandle;
    stHook[nIndex].szFunc = "CloseHandle";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

     ////////////////////////////////start v3 additions//////////////////////////////////////////////////
    // Timers
    stHook[nIndex].pProc = (PROC)MyCreateTimerQueue;
    stHook[nIndex].szFunc = "CreateTimerQueue";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyCreateTimerQueueTimer;
    stHook[nIndex].szFunc = "CreateTimerQueueTimer";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteTimerQueueTimer;
    stHook[nIndex].szFunc = "DeleteTimerQueueTimer";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteTimerQueueEx;
    stHook[nIndex].szFunc = "DeleteTimerQueueEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteTimerQueue;
    stHook[nIndex].szFunc = "DeleteTimerQueue";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    //critical section
    stHook[nIndex].pProc = (PROC)MyInitializeCriticalSection;
    stHook[nIndex].szFunc = "InitializeCriticalSection";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyInitializeCriticalSectionEx;
    stHook[nIndex].szFunc = "InitializeCriticalSectionEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyInitializeCriticalSectionAndSpinCount;
    stHook[nIndex].szFunc = "InitializeCriticalSectionAndSpinCount";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)MyDeleteCriticalSection;
    stHook[nIndex].szFunc = "DeleteCriticalSection";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    ////////////////////////////////end v3 additions//////////////////////////////////////////////////

    ASSERT( HANDLE_FUNC_COUNT == nIndex );
    HookDynamicLoadedFun( nIndex, stHook );

}

void RestoreHandleAlloc()
{
    HOOKFUNCDESC stHook[HANDLE_FUNC_COUNT] = {0};
    int nIndex = 0;
    stHook[nIndex].pProc = (PROC)pOrgCreateEventA;
    stHook[nIndex].szFunc = "CreateEventA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateEventW;
    stHook[nIndex].szFunc = "CreateEventW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateEventExA;
    stHook[nIndex].szFunc = "CreateEventExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateEventExW;
    stHook[nIndex].szFunc = "CreateEventExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenEventA;
    stHook[nIndex].szFunc = "OpenEventA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenEventW;
    stHook[nIndex].szFunc = "OpenEventW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMutexA;
    stHook[nIndex].szFunc = "CreateMutexA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMutexW;
    stHook[nIndex].szFunc = "CreateMutexW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMutexExA;
    stHook[nIndex].szFunc = "CreateMutexExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMutexExW;
    stHook[nIndex].szFunc = "CreateMutexExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenMutexA;
    stHook[nIndex].szFunc = "OpenMutexA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenMutexW;
    stHook[nIndex].szFunc = "OpenMutexW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateSemaphoreA;
    stHook[nIndex].szFunc = "CreateSemaphoreA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateSemaphoreW;
    stHook[nIndex].szFunc = "CreateSemaphoreW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateSemaphoreExA;
    stHook[nIndex].szFunc = "CreateSemaphoreExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateSemaphoreExW;
    stHook[nIndex].szFunc = "CreateSemaphoreExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenSemaphoreA;
    stHook[nIndex].szFunc = "OpenSemaphoreA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenSemaphoreW;
    stHook[nIndex].szFunc = "OpenSemaphoreW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateWaitableTimerA;
    stHook[nIndex].szFunc = "CreateWaitableTimerA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateWaitableTimerW;
    stHook[nIndex].szFunc = "CreateWaitableTimerW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateWaitableTimerExA;
    stHook[nIndex].szFunc = "CreateWaitableTimerExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateWaitableTimerExW;
    stHook[nIndex].szFunc = "CreateWaitableTimerExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenWaitableTimerA;
    stHook[nIndex].szFunc = "OpenWaitableTimerA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenWaitableTimerW;
    stHook[nIndex].szFunc = "OpenWaitableTimerW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileA;
    stHook[nIndex].szFunc = "CreateFileA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileW;
    stHook[nIndex].szFunc = "CreateFileW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileTransactedA;
    stHook[nIndex].szFunc = "CreateFileTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileTransactedW;
    stHook[nIndex].szFunc = "CreateFileTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileA;
    stHook[nIndex].szFunc = "FindFirstFileA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileW;
    stHook[nIndex].szFunc = "FindFirstFileW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileExA;
    stHook[nIndex].szFunc = "FindFirstFileExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileExW;
    stHook[nIndex].szFunc = "FindFirstFileExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileNameTransactedW ;
    stHook[nIndex].szFunc = "FindFirstFileNameTransactedW ";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileNameW;
    stHook[nIndex].szFunc = "FindFirstFileNameW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileTransactedA;
    stHook[nIndex].szFunc = "FindFirstFileTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstFileTransactedW;
    stHook[nIndex].szFunc = "FindFirstFileTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstStreamTransactedW;
    stHook[nIndex].szFunc = "FindFirstStreamTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstStreamW;
    stHook[nIndex].szFunc = "FindFirstStreamW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindClose;
    stHook[nIndex].szFunc = "FindClose";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenFileById;
    stHook[nIndex].szFunc = "OpenFileById";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgReOpenFile;
    stHook[nIndex].szFunc = "ReOpenFile";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateIoCompletionPort;
    stHook[nIndex].szFunc = "CreateIoCompletionPort";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateRestrictedToken;
    stHook[nIndex].szFunc = "CreateRestrictedToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDuplicateToken;
    stHook[nIndex].szFunc = "DuplicateToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDuplicateTokenEx;
    stHook[nIndex].szFunc = "DuplicateTokenEx";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenProcessToken;
    stHook[nIndex].szFunc = "OpenProcessToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenThreadToken;
    stHook[nIndex].szFunc = "OpenThreadToken";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstChangeNotificationA;
    stHook[nIndex].szFunc = "FindFirstChangeNotificationA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindFirstChangeNotificationW;
    stHook[nIndex].szFunc = "FindFirstChangeNotificationW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgFindCloseChangeNotification;
    stHook[nIndex].szFunc = "FindCloseChangeNotification";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMemoryResourceNotification;
    stHook[nIndex].szFunc = "CreateMemoryResourceNotification";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileMappingA;
    stHook[nIndex].szFunc = "CreateFileMappingA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileMappingW;
    stHook[nIndex].szFunc = "CreateFileMappingW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileMappingNumaA;
    stHook[nIndex].szFunc = "CreateFileMappingNumaA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateFileMappingNumaW;
    stHook[nIndex].szFunc = "CreateFileMappingNumaW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenFileMappingA;
    stHook[nIndex].szFunc = "OpenFileMappingA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenFileMappingW;
    stHook[nIndex].szFunc = "OpenFileMappingW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgHeapCreate;
    stHook[nIndex].szFunc = "HeapCreate";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgHeapDestroy;
    stHook[nIndex].szFunc = "HeapDestroy";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGlobalAlloc;
    stHook[nIndex].szFunc = "GlobalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGlobalReAlloc;
    stHook[nIndex].szFunc = "GlobalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgGlobalFree;
    stHook[nIndex].szFunc = "GlobalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLocalAlloc;
    stHook[nIndex].szFunc = "LocalAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLocalReAlloc;
    stHook[nIndex].szFunc = "LocalReAlloc";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgLocalFree;
    stHook[nIndex].szFunc = "LocalFree";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateProcessA;
    stHook[nIndex].szFunc = "CreateProcessA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateProcessW;
    stHook[nIndex].szFunc = "CreateProcessW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateProcessAsUserA;
    stHook[nIndex].szFunc = "CreateProcessAsUserA";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateProcessAsUserW;
    stHook[nIndex].szFunc = "CreateProcessAsUserW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateProcessWithLogonW;
    stHook[nIndex].szFunc = "CreateProcessWithLogonW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateProcessWithTokenW;
    stHook[nIndex].szFunc = "CreateProcessWithTokenW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenProcess;
    stHook[nIndex].szFunc = "OpenProcess";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateThread;
    stHook[nIndex].szFunc = "CreateThread";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateRemoteThread;
    stHook[nIndex].szFunc = "CreateRemoteThread";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgOpenThread;
    stHook[nIndex].szFunc = "OpenThread";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateJobObjectA;
    stHook[nIndex].szFunc = "CreateJobObjectA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateJobObjectW;
    stHook[nIndex].szFunc = "CreateJobObjectW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMailslotA;
    stHook[nIndex].szFunc = "CreateMailslotA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateMailslotW;
    stHook[nIndex].szFunc = "CreateMailslotW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreatePipe;
    stHook[nIndex].szFunc = "CreatePipe";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateNamedPipeA;
    stHook[nIndex].szFunc = "CreateNamedPipeA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateNamedPipeW;
    stHook[nIndex].szFunc = "CreateNamedPipeW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegCreateKeyExA;
    stHook[nIndex].szFunc = "RegCreateKeyExA";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegCreateKeyExW ;
    stHook[nIndex].szFunc = "RegCreateKeyExW";
    stHook[nIndex].lpszDllName = _T("Advapi32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegCreateKeyTransactedA;
    stHook[nIndex].szFunc = "RegCreateKeyTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegCreateKeyTransactedW;
    stHook[nIndex].szFunc = "RegCreateKeyTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenCurrentUser;
    stHook[nIndex].szFunc = "RegOpenCurrentUser";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenKeyA;
    stHook[nIndex].szFunc = "RegOpenKeyA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenKeyW;
    stHook[nIndex].szFunc = "RegOpenKeyW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenKeyExA;
    stHook[nIndex].szFunc = "RegOpenKeyExA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenKeyExW;
    stHook[nIndex].szFunc = "RegOpenKeyExW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenKeyTransactedA;
    stHook[nIndex].szFunc = "RegOpenKeyTransactedA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenKeyTransactedW;
    stHook[nIndex].szFunc = "RegOpenKeyTransactedW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegOpenUserClassesRoot;
    stHook[nIndex].szFunc = "RegOpenUserClassesRoot";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegCreateKeyA;
    stHook[nIndex].szFunc = "RegCreateKeyA";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegCreateKeyW;
    stHook[nIndex].szFunc = "RegCreateKeyW";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgRegCloseKey;
    stHook[nIndex].szFunc = "RegCloseKey";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDuplicateHandle;
    stHook[nIndex].szFunc = "DuplicateHandle";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCloseHandle;
    stHook[nIndex].szFunc = "CloseHandle";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;
     
    ////////////////////////////////start v3 additions//////////////////////////////////////////////////
    // Timers
    stHook[nIndex].pProc = (PROC)pOrgCreateTimerQueue;
    stHook[nIndex].szFunc = "CreateTimerQueue";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgCreateTimerQueueTimer;
    stHook[nIndex].szFunc = "CreateTimerQueueTimer";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteTimerQueueTimer;
    stHook[nIndex].szFunc = "DeleteTimerQueueTimer";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteTimerQueueEx;
    stHook[nIndex].szFunc = "DeleteTimerQueueEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteTimerQueue;
    stHook[nIndex].szFunc = "DeleteTimerQueue";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

     //critical section
    stHook[nIndex].pProc = (PROC)pOrgInitializeCriticalSection;
    stHook[nIndex].szFunc = "InitializeCriticalSection";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgInitializeCriticalSectionEx;
    stHook[nIndex].szFunc = "InitializeCriticalSectionEx";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgInitializeCriticalSectionAndSpinCount;
    stHook[nIndex].szFunc = "InitializeCriticalSectionAndSpinCount";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;

    stHook[nIndex].pProc = (PROC)pOrgDeleteCriticalSection;
    stHook[nIndex].szFunc = "DeleteCriticalSection";
    stHook[nIndex].lpszDllName = _T("Kernel32.dll");
    nIndex++;
    ////////////////////////////////end v3 additions//////////////////////////////////////////////////
    ASSERT( HANDLE_FUNC_COUNT == nIndex );
    HookDynamicLoadedFun( nIndex, stHook );
}

DWORD WINAPI DumpController( LPVOID pParam )
{
    AFX_MANAGE_STATE( AfxGetStaticModuleState());
    ConfigDlg dlg;
    dlg.Create( ConfigDlg::IDD );
    dlg.ShowWindow( SW_SHOW );
    if( IDOK != dlg.RunModalLoop())
    {
// 		HMODULE hHookDll = GetModuleHandle( _T("HookDll.dll"));
// 		FreeLibrary( hHookDll );
        return 0;
    }


    m_MemMap.InitHashTable( 2001 );

    //g_HookType = 3;
    if( HT_MEMORY == g_HookType )
    {
        HookMemAlloc();
    }
    else if( HT_GDI == g_HookType )
    {
        HookGDIAlloc();
    }
	else if( HT_HANDLE == g_HookType )
    {
        HookHandleAlloc();
    }
	else
	{
		//error
	}
 
    
    HANDLE hDumpEvent	 = CreateEvent( 0, TRUE, FALSE, DUMP_EVENT );
    HANDLE hMemRestEvent = CreateEvent( 0, TRUE, FALSE, CLEAR_LEAKS );
    HANDLE hSymBolInfo   = CreateEvent( 0, TRUE, FALSE, SHOW_PDB_INFO );
    HANDLE hArray[3] = { hDumpEvent, hMemRestEvent, hSymBolInfo };
    g_bHooked = true; 
    while( 1 )
    {
        DWORD dwWait = WaitForMultipleObjects( 3, hArray, FALSE, INFINITE );
        CSingleLock lockObj( &SyncObj, TRUE );
        g_bTrack = false;
        lockObj.Unlock();
        if( dwWait == WAIT_OBJECT_0 )
        {
            ResetEvent( hDumpEvent );
            DumpLeak();
        }
        else if( dwWait == WAIT_OBJECT_0 + 1)
        {
            lockObj.Lock();
            EmptyLeakMap();
            lockObj.Unlock();
            ResetEvent( hMemRestEvent );
            
        }
        else if( dwWait == WAIT_OBJECT_0 + 2)
        {
            ModuleInfo dlg;
            dlg.DoModal();
            ResetEvent( hSymBolInfo );
        }
        else if( dwWait == WAIT_OBJECT_0 + 3)// exit event
        {
            break;
        }
        lockObj.Lock();
        g_bTrack = true;
        lockObj.Unlock();
    }
    CloseHandle( hDumpEvent );
    CloseHandle( hMemRestEvent );
    CloseHandle( hSymBolInfo );
    return 0;
}

BOOL CHookDllApp::InitInstance() 
{
    HANDLE hThread = ::CreateThread( 0,0,DumpController, 0,0, 0 );
    CloseHandle(  hThread );    
    return CWinApp::InitInstance();
}

CString GetGDIHandleType( HGDIOBJ hObj, SIZE_T nType )
{
    CString csType;
    if( nType == IMAGE_ICON ) 
    {
        csType = _T("Icon");
        return csType;
    }
    else if( nType == IMAGE_CURSOR )
    {
        csType = _T("Cursor");
        return csType;
    }

    DWORD dwType = GetObjectType( hObj );
    switch( dwType )
    {
    case OBJ_BITMAP:
        csType = _T("Bitmap");
        break;
    case OBJ_BRUSH:
        csType = _T("Brush");
        break;
    case OBJ_COLORSPACE:
        csType = _T("Color space");
        break;
    case OBJ_DC:
        csType = _T( "Device context");
        break;
    case OBJ_ENHMETADC:
        csType = _T("Enhanced metafile DC");
        break;
    case OBJ_ENHMETAFILE:
        csType = _T("Enhanced metafile");
        break;
    case OBJ_EXTPEN:
        csType = _T("Extended pen");
        break;
    case OBJ_FONT:
        csType = _T("Font");
        break;
    case OBJ_MEMDC:
        csType = _T("Memory DC");
        break;
    case OBJ_METAFILE:
        csType = _T("Metafile");
        break;
    case OBJ_METADC:
        csType = _T("Metafile DC");
        break;
    case OBJ_PAL:
        csType = _T("Palette");
        break;
    case OBJ_PEN:
        csType = _T("Pen");
        break;
    case OBJ_REGION:
        csType = _T("Region");
        break;
    default:
        csType = _T("Unknown");
        break;
    }
    return csType;

}

CString GetHandleType( HGDIOBJ hObj, SIZE_T nType )
{
    CString csType;
    switch( nType)
    {
    case TYPE_EVENT_HANDLE:
        csType = _T("Event HANDLE");
        break;
    case TYPE_MUTEX_HANDLE:
        csType = _T("Mutex HANDLE");
        break;
    case TYPE_SEMAPHOR_HANDLE:
        csType = _T("Semaphore HANDLE");
        break;
    case TYPE_CRITICAL_SECTION_HANDLE:
        csType = _T("Critical section object");
        break;
    case TYPE_WAIT_TIMER_HANDLE:
        csType = _T("Waitable timer HANDLE");
        break;
    case TYPE_FILE_HANDLE:
        csType = _T("File HANDLE");
        break;
    case TYPE_TOKEN_HANDLE:
        csType = _T("Token HANDLE");
        break;
    case TYPE_CHANGE_NOFICATION_HANDLE:
        csType = _T("Change Notification HANDLE");
        break;
    case TYPE_MEMEORY_MAPPED_FILE_HANDLE:
        csType = _T("Memory mapped file HANDLE");
        break;
    case TYPE_MEMORY_HANDLE:
        csType = _T("Memory HANDLE");
        break;
    case TYPE_PROCESS_HANDLE:
        csType = _T("Process HANDLE");
        break;
    case TYPE_THREAD_HANDLE:
        csType = _T("Thread HANDLE");
        break;
    case TYPE_JOB_HANDLE:
        csType = _T("Job HANDLE");
        break;
    case TYPE_MAIL_SLOT_HANDLE:
        csType = _T("Mail Slot HANDLE");
        break;
    case TYPE_PIPE_HANDLE:
        csType = _T("Pipe HANDLE");
        break;
    case TYPE_REGISTRY_HANDLE:
        csType = _T("Registry HANDLE");
        break;
    case TYPE_TIMER_QUEUE:
        csType = _T("Timer queue HANDLE");
        break;
    default:
        csType = _T("unknown type");
        break;
    }
    return csType;
}

void DumpLeak()
{
    if( 0 == m_MemMap.GetCount())
    {
        AfxMessageBox( "No leak detected" );
        return;
    }
    CFileDialog dlg( FALSE, _T(".txt"), _T("Dump.txt"));
    if( IDOK != dlg.DoModal())
    {
        return;
    }
    CFile File;
    //if( !File.Open( _T("D:\\Dump.txt"), CFile::modeCreate|CFile::modeWrite ))
    if( !File.Open( dlg.GetPathName(), CFile::modeCreate|CFile::modeWrite ))
    {
        AfxMessageBox( "Failed to create file" );
        return;
    }
    HANDLE hProcess = GetCurrentProcess();
    DWORD64 dwDisplacement;

    BYTE SymBol[ sizeof(SYMBOL_INFO) + STACKWALK_MAX_NAMELEN ] = {0};
    SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)SymBol;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = STACKWALK_MAX_NAMELEN;

    IMAGEHLP_LINE64 Line = {0};
    Line.SizeOfStruct = sizeof( IMAGEHLP_LINE64 );

    MEM_INFO stInfo;
    LPVOID lMem;
    POSITION pos = m_MemMap.GetStartPosition();
    while( pos )
    {
        m_MemMap.GetNextAssoc( pos, lMem, stInfo );
        CString csLength;
        if( HT_MEMORY == g_HookType )
        {
            csLength.Format( "-->Bytes allocated -- %d\r\n\r\n", stInfo.nMemSize );
        }
        else if( HT_GDI == g_HookType )
        {
            CString csType = GetGDIHandleType( lMem, stInfo.nMemSize );
            csLength.Format( "-->%s -- 0x%x\r\n\r\n", csType, lMem );
            //csLength.Format( "Bytes allocated -- %d\r\n\r\n", stInfo.nMemSize );
        }
        else if( HT_HANDLE == g_HookType )
        {
            CString csType = GetHandleType( lMem, stInfo.nMemSize );
            csLength.Format( "-->%s -- 0x%x\r\n\r\n", csType, lMem );
        }
        
        File.Write( csLength, csLength.GetLength());
        int nCount = (int)stInfo.parCallStack->GetCount();
        for( int nIdx =1;nIdx< nCount;nIdx++ )
        {
            DWORD64 dwOffset = (*(stInfo.parCallStack)).GetAt( nIdx );

            CString cs;
            CString csFunctionName;
            
            if( !SymFromAddr( hProcess, dwOffset, &dwDisplacement, pSymbol ))
            {
                /*csFunctionName = "Unknown";*/                
                MEMORY_BASIC_INFORMATION stMemoryInfo;                 
                HMODULE hModule = 0;
                // Get the information about the virtual address space of the calling process
                if( VirtualQuery( (void*)dwOffset, &stMemoryInfo, sizeof( stMemoryInfo ))
                                                                            != 0 )
                {            
                    hModule = reinterpret_cast<HMODULE>( 
                                                    stMemoryInfo.AllocationBase);
                }
                // Get the exe's or ddl's file name
                DWORD dwFileNameLength = GetModuleFileName( hModule, csFunctionName.GetBuffer( MAX_PATH ), MAX_PATH );
                csFunctionName.ReleaseBuffer();
            }
            else
            {
                csFunctionName = pSymbol->Name;
            }
            DWORD dwLine = 0;
            if( SymGetLineFromAddr64( hProcess, dwOffset, &dwLine, &Line ))
            {
                CString csFormatString;
                int n = 40 - csFunctionName.GetLength();
                csFormatString.Format( _T("%s%d%s"), _T("%s%"), n, _T("s%s(%d)"));
                cs.Format( csFormatString, csFunctionName, _T(" "), Line.FileName, Line.LineNumber );
            }
            else
            {
                cs = csFunctionName;
            }
//            CString cs = (*(stInfo.parCallStack)).GetAt( nIdx);
            cs += _T("\r\n");
            File.Write( cs, cs.GetLength());
        }        
        TCHAR tc[] = {"------------------------------------------------\r\n\r\n\r\n\r\n"};
        File.Write( tc, sizeof(tc) - 1);
    }
    File.Close();

    if( IDYES == AfxMessageBox( _T("Dump saved.\nDo you want to open it?" ) , MB_YESNO ))
    {
        CString csDllPath;
        HMODULE hHookDll = GetModuleHandle( _T("HookDll.dll"));
        if( !GetModuleFileName( hHookDll, csDllPath.GetBuffer( MAX_PATH), MAX_PATH ))
        {
            return;
        }
        csDllPath.ReleaseBuffer();
        int nPos = csDllPath.ReverseFind( _T('\\'));
        if( 0 >= nPos )
        {
            return;
        }
        csDllPath = csDllPath.Left( nPos + 1 );
        csDllPath += _T("DumpViewer.exe");

        CString csFileName = _T("\"") + dlg.GetPathName();
        csFileName += _T("\"");
        ShellExecute( NULL, _T("open"), csDllPath, csFileName, 0, SW_SHOWDEFAULT );
    }
    

}
void EmptyLeakMap()
{
    POSITION pos = m_MemMap.GetStartPosition();
    while( pos )
    {
        LPVOID lpMem = 0;
        MEM_INFO stInfo;
        m_MemMap.GetNextAssoc( pos, lpMem, stInfo );
        //delete stInfo.parCallStack;
        
        stInfo.parCallStack->~STACK_ARRAY();
        DeleteMem( stInfo.parCallStack);
    }
    m_MemMap.RemoveAll();
}
int CHookDllApp::ExitInstance() 
{
    try
    {   
        // Restore the hooks       
        g_bHooked = false;		
        EmptyLeakMap();
        if( HT_MEMORY == g_HookType )
        {
            RestoreMemHooks();
        }
        else if( HT_GDI == g_HookType )
        {
            RestoreGDIHook();
        }
        else if( HT_HANDLE == g_HookType )
        {
            RestoreHandleAlloc();
        }
    }
    catch (...)
    {
        
    }
    //DumpLeak();
    return CWinApp::ExitInstance();
}