using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Popups;

namespace PE_Viewer
{
    public static class Exceptions
    {
        public static async void ThrownExceptionError(System.Exception ex)
        {

            var ThrownException = new MessageDialog(ex.Message + "\n" + "\n" + ex.ToString());
            ThrownException.Commands.Add(new UICommand("Close"));
            await ThrownException.ShowAsync();
        }
    }
}
