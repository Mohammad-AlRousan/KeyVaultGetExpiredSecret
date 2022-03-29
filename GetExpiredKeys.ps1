[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true)][string]$KeyVaultName
)



$ExpiredSecrets=@()

 $NearExpirationSecrets=@()

$Expiry_Notification_Days=30
$current_date=Get-Date 


$KVindex=0

 

# Check if the key-vault exists or not
$checkkeyvault=(Get-AzKeyVault -VaultName $keyvaultname)
echo $checkkeyvault

     if ($checkkeyvault)
    {
           # echo "KeyVault is present.Now,Checking the key-vault secret expiry dates..."

           # Check the expiry date
           $keyvaultsecretname=(Get-AzKeyVaultSecret -VaultName $keyvaultname)
           # echo "KeyVaultSecretName : $keyvaultsecretname"
           $keyvaultsecretvexpirydate= ((Get-AzKeyVaultSecret -VaultName $keyvaultname).Expires)
           # echo "KeyVaultExpiryDate : $keyvaultsecretvexpirydate"

        # Now,For Each Key-Vault Expiry Date
        foreach ($expirydate in $keyvaultsecretvexpirydate)        
        {         
           #determine days until expiration                    
           if ( $expirydate )
           {
              $timediff=NEW-TIMESPAN -Start $current_date -End $expirydate
              $days_until_expiration=$timediff.Days

              # echo "Days Until Expiration is : $days_until_expiration"

              #Check if Key-Vault Secrets are expiring in n days
              if( $days_until_expiration -le $Expiry_Notification_Days )
               {    
                        if( $days_until_expiration -le 0 )
                                      {    
                                                    $ExpiredSecrets += New-Object PSObject -Property @{
                                                                    SecretName     = $keyvaultsecretname[$KVindex].Name;
                                                                    Category       = 'SecretAlreadyExpired';
                                                                    KeyVaultName   = $KeyVaultName;
                                                                    ExpirationDate = $expirydate;
                                                    }
                                            

                                      }
                      else
                      {
                                                    $NearExpirationSecrets += New-Object PSObject -Property @{
                                                                    SecretName     = $keyvaultsecretname[$KVindex].Name;
                                                                    Category       = 'SecretNearExpiration';
                                                                    KeyVaultName   = $KeyVaultName;
                                                                    ExpirationDate = $expirydate;
                                                    }
                      }
               }
           }
              $KVindex+=1
        }
    }
    else
    {
          echo "Key-Vault Doesn't exist..Please check the correct Key-Vault Name"
    }

Write-Output "Total number of expired secrets: $($ExpiredSecrets.Count)"
Write-Output $($ExpiredSecrets) | out-string -Width 160

Write-Output "Total number of secrets near expiration: $($NearExpirationSecrets.Count)"
Write-Output $($NearExpirationSecrets) | out-string -Width 160
