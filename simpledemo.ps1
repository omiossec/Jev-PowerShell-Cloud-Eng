# import module 
Import-Module ../Jev/Jev.psd1 -Force

# create the state, the context for the question
$feedback = [pscustomobject] @{
    message = 'The customer is blocked by a connection issue to the database.'
}

# define the criteria for the question
$criteria = @{
    support = 'The issue needs technical support.'
    sales   = 'The issue concerns sales.'
}

# create the question based on the criteria
$question = New-JevQuestion -Name TeamRouting -Type Choice -Instructions 'Which team should handle this?' -Criteria $criteria

# invoke the question with the current state
$result = Invoke-Jev -State $feedback -Question $question

# check the result of the question
$result.answers.TeamRouting