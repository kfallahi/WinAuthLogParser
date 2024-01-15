Function WinAuthLog-Parser {
	param (
		[Parameter(Mandatory = $false)] [String]$LogPath,
		[Parameter(Mandatory = $false)] [String]$UserList,
		[Parameter(Mandatory = $true)]  [String]$OutDir
	)

	$d=Get-Date -Format "yyyyMMddHHmmss"

Function Get-Eid4624{
	if ($UserList){
		if (Test-Path $UserList){
			$users = gc $UserList
		}else{
			$users=''
		}
	}else{
		$users=''
	}
	foreach ($u in $users){
		$filename = 'events_4624_' + $u + '_' + $d
		if ($LogPath){
			try{
				$Events = Get-WinEvent -FilterHashtable @{ Path = $LogPath; ID = 4624; data = $u } -ErrorAction Stop
			}catch [Exception]{
				if ($_.Exception -match "No events were found that match the specified selection criteria") {
					'Error: No events found' | Out-File $OutDir\$filename.txt
				}else{
					'Error: ' + $_.Exception.Message | Out-File $OutDir\$filename.txt
				}
				continue
			}
		}else{
			try{
				$Events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4624; data = $u } -ErrorAction Stop
			}catch [Exception]{
				if ($_.Exception -match "No events were found that match the specified selection criteria") {
					'Error: No events found' | Out-File $OutDir\$filename.txt
				}else{
					'Error: ' + $_.Exception.Message | Out-File $OutDir\$filename.txt
				}
				continue
			}
		}
		$E_Parsed = New-Object System.Collections.ArrayList
		foreach ($e in $Events){
			$eventXML = [xml]$e.ToXml()
			$tempA = @{
				EventID   = $e.id
				EventTime = $e.timecreated
				UserName  = $eventXML.Event.EventData.Data[5].'#text'
				LogonType = $eventXML.Event.EventData.Data[8].'#text'
				WorkstationName = $eventXML.Event.EventData.Data[11].'#text'
				ProcessName = $eventXML.Event.EventData.Data[17].'#text'
				IP	      = $eventXML.Event.EventData.Data[18].'#text'
				Port	  = $eventXML.Event.EventData.Data[19].'#text'
    			LogonID	  = $eventXML.Event.EventData.Data[7].'#text'
			}
			$tempB = New-Object -TypeName PSObject -Property $tempA
			$E_Parsed.Add($tempB) > $null
		}
		$E_Parsed | Export-CSV $OutDir\$filename.csv -NoTypeInformation
	}
}

Function Get-Eid4625{
	$reasons= @{
		"0xC0000064" = ", user name does not exist"
		"0xC000006A" = ", user name is correct but the password is wrong"
		"0xC0000234" = ", user is currently locked out"
		"0xC0000072" = ", account is currently disabled"
		"0xC000006F" = ", user tried to logon outside his day of week or time of day restrictions"
		"0xC0000070" = ", workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)"
		"0xC0000193" = ", account expiration"
		"0xC0000071" = ", expired password"
		"0xC0000133" = ", clocks between DC and other computer too far out of sync"
		"0xC0000224" = ", user is required to change password at next logon"
		"0xC0000225" = ", evidently a bug in Windows and not a risk"
		"0xc000015b" = ", The user has not been granted the requested logon type (aka logon right) at this machine"
	}
	$filename = 'events_4625_' + $d
	if ($LogPath){
		try{
			$Events = Get-WinEvent -FilterHashtable @{ Path = $LogPath; ID = 4625 } -ErrorAction Stop
		}catch [Exception]{
			if ($_.Exception -match "No events were found that match the specified selection criteria") {
				'Error: No events found' | Out-File $OutDir\$filename.txt
			}else{
				'Error: ' + $_.Exception.Message | Out-File $OutDir\$filename.txt
			}
			continue
		}
	}else{
		try{
			$Events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4625 } -ErrorAction Stop
		}catch [Exception]{
			if ($_.Exception -match "No events were found that match the specified selection criteria") {
				'Error: No events found' | Out-File $OutDir\$filename.txt
			}else{
				'Error: ' + $_.Exception.Message | Out-File $OutDir\$filename.txt
			}
			continue
		}
	}
	$E_Parsed = New-Object System.Collections.ArrayList
	foreach ($e in $Events){
		$eventXML = [xml]$e.ToXml()
		$tempA = @{
			EventID   = $e.id
			EventTime = $e.timecreated
			UserName  = $eventXML.Event.EventData.Data[5].'#text'
			LogonType = $eventXML.Event.EventData.Data[10].'#text'
			ProcessName = $eventXML.Event.EventData.Data[18].'#text'
			IP	      = $eventXML.Event.EventData.Data[19].'#text'
			Failure_Status =  ($eventXML.Event.EventData.Data[7].'#text') + $reasons[($eventXML.Event.EventData.Data[7].'#text')]
			Failure_SubStatus = ($eventXML.Event.EventData.Data[9].'#text') + $reasons[($eventXML.Event.EventData.Data[9].'#text')]
			SubjectUserName = $eventXML.Event.EventData.Data[1].'#text'
   			LogonID = $eventXML.Event.EventData.Data[3].'#text'
			SubjectDomainName = $eventXML.Event.EventData.Data[2].'#text'
			TargetDomainName = $eventXML.Event.EventData.Data[6].'#text'
		}
		
		
		$tempB = New-Object -TypeName PSObject -Property $tempA
		$E_Parsed.Add($tempB) > $null
	}
	$E_Parsed | Export-CSV $OutDir\$filename.csv -NoTypeInformation
}

Get-Eid4624
Get-Eid4625

}
