Function Get-AuditPolicy {

    $CurrentSettings = auditpol /get /category:* /r | ConvertFrom-Csv

    # Functions to create a new security object
    function Get-AuditType {
    param($RawValue)
        switch($RawValue)
        { 
            "No Auditing"{0}
            "Success"{1} 
            "Failure"{2} 
            "Success and Failure"{3}
        }
    }
    Function New-AuditObj {
    Param($Category,$SubCategory,$Value)

        $Out = '' | Select-Object Category, SubCategory, RawValue, ConfiguredValue, RequiredValue, CheckResult, check_type
        $Out.Category = $Category
        $Out.SubCategory = $SubCategory
        $Out.RawValue = Get-AuditType $Value
        $Out.ConfiguredValue = $Value
        $Out.RequiredValue = $null
        $Out.CheckResult = $false
        $Out.check_type = 'AuditPol'
        $Out

    }

    $Categories = @{
        # System category
        'Security System Extension'='System'
        'System Integrity'='System'
        'IPsec Driver'='System'
        'Other System Events'='System'
        'Security State Change'='System'
        
        # Logon/Logoff category
        'Logon'='Logon/Logoff'
        'Logoff'='Logon/Logoff'
        'Account Lockout'='Logon/Logoff'
        'IPsec Main Mode'='Logon/Logoff'
        'IPsec Quick Mode'='Logon/Logoff'
        'IPsec Extended Mode'='Logon/Logoff'
        'Special Logon'='Logon/Logoff'
        'Other Logon/Logoff Events'='Logon/Logoff'
        'Network Policy Server'='Logon/Logoff'
        'User / Device Claims'='Logon/Logoff'
        
        # Object Access category
        'File System'='Object Access'
        'Registry'='Object Access'
        'Kernel Object'='Object Access'
        'SAM'='Object Access'
        'Certification Services'='Object Access'
        'Application Generated'='Object Access'
        'Handle Manipulation'='Object Access'
        'File Share'='Object Access'
        'Filtering Platform Packet Drop'='Object Access'
        'Filtering Platform Connection'='Object Access'
        'Other Object Access Events'='Object Access'
        'Detailed File Share'='Object Access'
        'Removable Storage'='Object Access'
        'Central Policy Staging'='Object Access'

        # Privilege Use category    
        'Sensitive Privilege Use'='Privilege Use'
        'Non Sensitive Privilege Use'='Privilege Use'
        'Other Privilege Use Events'='Privilege Use'

        # Detailed Tracking category    
        'Process Termination'='Detailed Tracking'
        'DPAPI Activity'='Detailed Tracking'
        'RPC Events'='Detailed Tracking'
        'Process Creation'='Detailed Tracking'
        'PNP Activity'='Detailed Tracking'

        # Policy Change category
        'Audit Policy Change'='Policy Change'
        'Authentication Policy Change'='Policy Change'
        'Authorization Policy Change'='Policy Change'
        'MPSSVC Rule-Level Policy Change'='Policy Change'
        'Filtering Platform Policy Change'='Policy Change'
        'Other Policy Change Events'='Policy Change'

        # Account Management category    
        'User Account Management'='Account Management'
        'Computer Account Management'='Account Management'
        'Security Group Management'='Account Management'
        'Distribution Group Management'='Account Management'
        'Application Group Management'='Account Management'
        'Other Account Management Events'='Account Management'

        # DS Access category
        'Directory Service Changes'='DS Access'
        'Directory Service Replication'='DS Access'
        'Detailed Directory Service Replication'='DS Access'
        'Directory Service Access'='DS Access'

        # Account Logon category
        'Kerberos Service Ticket Operations'='Account Logon'
        'Other Account Logon Events'='Account Logon'
        'Kerberos Authentication Service'='Account Logon'
        'Credential Validation'='Account Logon'
    }

    $CurrentSettings | ?{ $_.Subcategory -ne $null } | Foreach{

    if($Categories.keys -contains $_.SubCategory){
        New-AuditObj -Category $Categories.$($_.SubCategory) -SubCategory $_.SubCategory -Value $_.'Inclusion Setting'
    }else{

        New-AuditObj -Category 'Unknown' -SubCategory $_.SubCategory -Value $_.'Inclusion Setting'
    }


    }

}#end