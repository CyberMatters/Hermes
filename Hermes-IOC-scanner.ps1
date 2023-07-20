# Copyright 2023 Dany GIANG
#Script written by Dany Giang aka CyberMatters

param([Parameter(Mandatory=$true)]$IOC_location,[Parameter(Mandatory=$true)]$target_folder,[string[]]$include_file_extension,[string[]]$exclude_file_extension)

Clear-Host
Write-Host "`n"
Write-Host ******************************************`n
Write-Host ***************** HERMES *****************`n
Write-Host **** by Dany Giang aka CyberMatters ****`n
Write-Host ******************************************`n

$ioc_list = Import-Csv -Path $IOC_location -Delimiter ","

$file_time = Get-Date -Format "ddMMyyyy-hhmmss"
$computer = $env:computername
$outfile_name = ".\ioc-output-scanner-$computer-$file_time.csv"

$start_time = Get-Date -Format "dd/MM/yyyy hh:mm:ss"


if ($PSBoundParameters.ContainsKey('include_file_extension')){

    foreach ($file in (Get-ChildItem -Path $target_folder -Recurse)){

        $FullName = $file.FullName

        if(Test-Path -Path $FullName -PathType Leaf){ #Check if item is a file

            $match = $file.Name -match ".+\.(?<extension>.*$)" #file extension regex

            $file_extension = $matches['extension']

            if ($file_extension -in $include_file_extension){ #Apply file extension inclusion filter

            try{

                $signer1 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[0].split('=')[1]
                $signer2 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[1].split('=')[1]
                $signer3 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[2].split('=')[1]

                if (($signer1 -ne "Microsoft Corporation") -and ($signer2 -ne "Microsoft Corporation") -and ($signer3 -ne "Microsoft Corporation")){#Do not scan files signed my Microsoft
                    
                        $SHA256 = (Get-FileHash -Algorithm SHA256 -Path $FullName).Hash
                        $SHA1 = (Get-FileHash -Algorithm SHA1 -Path $FullName).Hash
                        $MD5 = (Get-FileHash -Algorithm MD5 -Path $FullName).Hash

                        Write-Output "Scanning $FullName"

                        foreach ($ioc in $ioc_list){


                            if ($SHA256 -eq $ioc.hash_value){

                                $newRow =[pscustomobject]@{
                                    'filename' = $FullName
                                    'hash_type' = 'SHA256'
                                    'hash_value' = $SHA256
                                    'description' = $ioc.description
                                }

                                $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                                break #If SHA256 matches, no need to compute SHA1
                            }

                            if ($SHA1 -eq $ioc.hash_value){
                    
                                $newRow =[pscustomobject]@{
                                    'filename' = $FullName
                                    'hash_type' = 'SHA1'
                                    'hash_value' = $SHA1
                                    'description' = $ioc.description
                                }

                                $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                                break #If SHA1 matches, no need to compute SHA1

                            }             

                            if ($SHA1 -eq $ioc.hash_value){

                                $newRow =[pscustomobject]@{
                                    'filename' = $FullName
                                    'hash_type' = 'MD5'
                                    'hash_value' = $MD5
                                    'description' = $ioc.description
                                }

                                $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                                break

                            }
         
                        }

                    }

                }catch{}
            } 
    
        }
    }

}

elseif ($PSBoundParameters.ContainsKey('exclude_file_extension')){

    foreach ($file in (Get-ChildItem -Path $target_folder -Recurse)){

        $FullName = $file.FullName

        if(Test-Path -Path $FullName -PathType Leaf){ #Check if item is a file
        
            $match = $file.Name -match ".+\.(?<extension>.*$)" #file extension regex

            $file_extension = $matches['extension']

            if ($file_extension -notin $exclude_file_extension){ #Apply file extension inclusion filter

                try{

                    $signer1 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[0].split('=')[1]
                    $signer2 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[1].split('=')[1]
                    $signer3 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[2].split('=')[1]

                    if (($signer1 -ne "Microsoft Corporation") -and ($signer2 -ne "Microsoft Corporation") -and ($signer3 -ne "Microsoft Corporation")){ #Do not scan files signed my Microsoft
            
                        $SHA256 = (Get-FileHash -Algorithm SHA256 -Path $FullName).Hash
                        $SHA1 = (Get-FileHash -Algorithm SHA1 -Path $FullName).Hash
                        $MD5 = (Get-FileHash -Algorithm MD5 -Path $FullName).Hash

                        Write-Output "Scanning $FullName"

                        foreach ($ioc in $ioc_list){


                            if ($SHA256 -eq $ioc.hash_value){

                                $newRow =[pscustomobject]@{
                                    'filename' = $FullName
                                    'hash_type' = 'SHA256'
                                    'hash_value' = $SHA256
                                    'description' = $ioc.description
                                }

                                $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                                break #If SHA256 matches, no need to compute SHA1
                            }

                            if ($SHA1 -eq $ioc.hash_value){
                    
                                $newRow =[pscustomobject]@{
                                    'filename' = $FullName
                                    'hash_type' = 'SHA1'
                                    'hash_value' = $SHA1
                                    'description' = $ioc.description
                                }

                                $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                                break #If SHA1 matches, no need to compute SHA1

                            }             

                            if ($SHA1 -eq $ioc.hash_value){

                                $newRow =[pscustomobject]@{
                                    'filename' = $FullName
                                    'hash_type' = 'MD5'
                                    'hash_value' = $MD5
                                    'description' = $ioc.description
                                }

                                $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                                break

                            }
         
                        }

                    }

                }catch{}

            }
    
        }

    }

}

else{

    foreach ($file in (Get-ChildItem -Path $target_folder -Recurse)){

        $FullName = $file.FullName

        if(Test-Path -Path $FullName -PathType Leaf){ #Check if item is a file
        
            try{

                $signer1 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[0].split('=')[1]
                $signer2 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[1].split('=')[1]
                $signer3 = (Get-AuthenticodeSignature $fullname).SignerCertificate.subject.split(',')[2].split('=')[1]

                if (($signer1 -ne "Microsoft Corporation") -and ($signer2 -ne "Microsoft Corporation") -and ($signer3 -ne "Microsoft Corporation")){ #Do not scan files signed my Microsoft
            
                    $SHA256 = (Get-FileHash -Algorithm SHA256 -Path $FullName).Hash
                    $SHA1 = (Get-FileHash -Algorithm SHA1 -Path $FullName).Hash
                    $MD5 = (Get-FileHash -Algorithm MD5 -Path $FullName).Hash

                    Write-Output "Scanning $FullName"

                    foreach ($ioc in $ioc_list){


                        if ($SHA256 -eq $ioc.hash_value){

                            $newRow =[pscustomobject]@{
                                'filename' = $FullName
                                'hash_type' = 'SHA256'
                                'hash_value' = $SHA256
                                'description' = $ioc.description
                            }

                            $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                            break #If SHA256 matches, no need to compute SHA1
                        }

                        if ($SHA1 -eq $ioc.hash_value){
                    
                            $newRow =[pscustomobject]@{
                                'filename' = $FullName
                                'hash_type' = 'SHA1'
                                'hash_value' = $SHA1
                                'description' = $ioc.description
                            }

                            $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                            break #If SHA1 matches, no need to compute SHA1

                        }             

                        if ($SHA1 -eq $ioc.hash_value){

                            $newRow =[pscustomobject]@{
                                'filename' = $FullName
                                'hash_type' = 'MD5'
                                'hash_value' = $MD5
                                'description' = $ioc.description
                            }

                            $newRow | Export-Csv -Path $outfile_name -NoTypeInformation -Force -Append
                            break

                        }
         
                    }

                }

            }catch{}

        }
    
    }

}

$end_time = Get-Date -Format "dd/MM/yyyy hh:mm:ss"

$duration = NEW-TIMESPAN -Start $start_time -End $end_time

Write-Output "`r`nThe scan is finished`r`n"
Write-Output "Start time : $start_time"
Write-Output "End time : $end_time"
Write-Output "Duration : $duration"
