$situation= 'a'
Describe "situation '$situation'" {
    It 'works as expected' {
        $true | Should -BeTrue
    }
}
