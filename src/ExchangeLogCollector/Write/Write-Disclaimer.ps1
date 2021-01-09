Function Write-Disclaimer {
    $display = @"

        Exchange Log Collector v{0}

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
        BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

        -This script will copy over data based off the switches provided.
        -We will check for at least {1} GB of free space at the local target directory BEFORE
            attempting to do the remote execution. It will continue to check to make sure that we have
            at least {2} GB of free space throughout the data collection. If some data is determined
            that if we were to copy it over it would place us over that threshold, we will not copy that
            data set over. The script will continue to run while still constantly check the free space
            available before doing a copy action.
        -Please run this script at your own risk.

"@ -f $scriptVersion, ($Script:StandardFreeSpaceInGBCheckSize = 10), $Script:StandardFreeSpaceInGBCheckSize

    Clear-Host
    Write-ScriptHost -WriteString $display -ShowServer $false
    if (-not($AcceptEULA)) {
        Enter-YesNoLoopAction -Question "Do you wish to continue? " -YesAction {} -NoAction { exit }
    }
}