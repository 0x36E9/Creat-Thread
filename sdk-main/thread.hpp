#pragma once

#include "stdafx.hpp"
#include "structs.hpp"

class thread
{
private:
	struct thread_t
	{
		uint32_t id;
		int32_t state;
		int32_t wait_reason;
	};

	// enumerate all threads of current process
	static bool enumerate( std::vector<thread_t> * );
public:
	thread( ) = default;
	~thread( ) = default;

	// conventional createthread with hidden thread option
	static uint32_t create( void *, bool = true );

	// check if thread is suspended or closed by id
	static bool suspended_or_closed( uint32_t );
};

uint32_t thread::create( void *address, bool hidden )
{
	uint32_t id {};

	auto handle = CreateThread( nullptr, 0ul, reinterpret_cast< LPTHREAD_START_ROUTINE >( address ),
								nullptr, CREATE_SUSPENDED, reinterpret_cast< LPDWORD >( &id ) );

	if ( handle == INVALID_HANDLE_VALUE )
		return 0;

	if ( hidden )
	{
		using fnNtSetInformationThread = long( __stdcall * )( void *, unsigned int, void *, unsigned long );
		const auto pNtSetInformationThread = reinterpret_cast< fnNtSetInformationThread >( GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtSetInformationThread" ) );

		if ( pNtSetInformationThread( handle, 17, nullptr, 0 ) != STATUS_SUCCESS )
		{
			TerminateThread( handle, 0 );
			CloseHandle( handle );

			return 0;
		}
	}

	ResumeThread( handle );
	CloseHandle( handle );

	return id;
}

bool thread::suspended_or_closed( uint32_t id )
{
	std::vector<thread_t> threads {};

	if ( !enumerate( &threads ) )
		return true;

	for ( const auto &thread : threads )
	{
		if ( thread.id != id )
			continue;

		return ( thread.state == 5 && thread.wait_reason == 5 ) ? true : false; // waiting & suspended
	}

	return true;
}

bool thread::enumerate( std::vector<thread_t> *output )
{
	using fnNtQuerySystemInformation = long( __stdcall * )( unsigned int, void *, unsigned long, unsigned long * );
	auto pNtQuerySystemInformation = reinterpret_cast< fnNtQuerySystemInformation >( GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQuerySystemInformation" ) );

	unsigned long needed = 0;
	if ( pNtQuerySystemInformation( 5, nullptr, 0, &needed ) != STATUS_INFO_LENGTH_MISMATCH )
		return false;

	auto spi = reinterpret_cast< PSYSTEM_PROCESS_INFORMATION >( malloc( needed ) );

	if ( pNtQuerySystemInformation( 5, spi, needed, nullptr ) != STATUS_SUCCESS )
	{
		free( spi );
		return false;
	}

	for ( auto process = spi; process; process = reinterpret_cast< PSYSTEM_PROCESS_INFORMATION >( reinterpret_cast< uint8_t * >( process ) + process->NextEntryOffset ) )
	{
		if ( process->UniqueProcessId != reinterpret_cast< void * >( GetCurrentProcessId( ) ) )
			continue;

		auto thread = reinterpret_cast< PSYSTEM_THREAD_INFORMATION >( process + 1 );

		for ( auto i { 0ul }; i < process->NumberOfThreads; ++i )
		{
			output->emplace_back( reinterpret_cast< uint32_t >( thread->ClientId.UniqueThread ), thread->ThreadState, thread->WaitReason );
			thread++;
		}

		free( spi );
		return true;
	}

	free( spi );
	return false;
}
