<#
	Accepted Comparison Operators:
		eq             Equal
		ne             Not equal
		ge             Greater than or equal
		gt             Greater than
		lt             Less than
		le             Less than or equal
		like           Wildcard comparison (use * for wildcard)
		notlike        Wildcard comparison (use * for wildcard)
		between        Greater than or equal to value and less than or equal than value2
		list		   compares to arrays and checks for differences if a difference is observed then a failure is returned
#>
Function Compare-Values {
param($ObtainedValue=0,$Value=0,$Value2=0,$Comparison='eq')

    if($Comparison -eq 'list')
	{
		# split if string, split using the same char as the policy
		# as the char used for split should always match the expecting obtained value
		if($ObtainedValue -is [string])
		{
			$ObtainedValue = $ObtainedValue.Split($Value2)
		}
		
        if((Test-IsNull -objectToCheck $Value) -and (Test-IsNull -objectToCheck $ObtainedValue))
        {
            'Pass'
        }elseif((Test-IsNull -objectToCheck $Value) -eq $false -and (Test-IsNull -objectToCheck $ObtainedValue) -eq $true){
            'Fail'
        }else{

		    $comres = Compare-Object -ReferenceObject @($Value.Split($Value2)) -DifferenceObject @($ObtainedValue)
		    if($comres)
		    {
			    'Fail'
		    }else{
			    'Pass'
		    }
        }
	}elseif($Comparison -eq 'between')
	{
		if($ObtainedValue -ge $Value -and $ObtainedValue -le $Value2)
		{
			'Pass'
		}else{
			'Fail'
		}
	}else{
		if((Invoke-Expression ('$ObtainedValue -' + $Comparison + ' $Value')))
		{
			'Pass'
		}else{
			'Fail'
		}
	}

}