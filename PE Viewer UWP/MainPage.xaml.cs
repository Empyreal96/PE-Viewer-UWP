using PeNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.Storage;
using Windows.Storage.AccessCache;
using Windows.Storage.Pickers;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Imaging;
using Windows.UI.Xaml.Navigation;
using WinUniversalTool.WebViewer;


// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace PE_Viewer
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public string SelectedPEFile { get; set; }
        public string PEImports { get; set; }
        public string PEFilename { get; set; }
        public byte[] bytes { get; set; }
        public byte[] buff { get; set; }
        public static string pdbname { get; set; }
        public static string pdbhash { get; set; }
        public static string pdbUri { get; set; }


        internal const string MicrosoftSymbolsUrl = "https://msdl.microsoft.com/download/symbols";

        public StorageFolder LocalFolder = ApplicationData.Current.LocalFolder;
        ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
        public MainPage()
        {
            this.InitializeComponent();


            ProgRing.IsActive = false;
            ProgRing.Visibility = Visibility.Collapsed;
            ProgRing.IsEnabled = false;
            PEValidBoarder.Visibility = Visibility.Collapsed;
            DOSBorder.Visibility = Visibility.Collapsed;
            pdbDownld.Visibility = Visibility.Collapsed;
            HashBoarder.Visibility = Visibility.Collapsed;
            PESomeBorder.Visibility = Visibility.Collapsed;
            PEHeadBoarder.Visibility = Visibility.Collapsed;
            PEMetaBorder2.Visibility = Visibility.Collapsed;
            CopyrightBorder.Visibility = Visibility.Collapsed;
            PEStrings.IsPELoaded = "No";
            PEInfoHeaderBox.Text = "Open an executable (.exe) or Library (.dll) to view Information about it.";


        }

        public async void OpenFileButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new Windows.Storage.Pickers.FileOpenPicker();
                picker.ViewMode = Windows.Storage.Pickers.PickerViewMode.List;
                picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.ComputerFolder;
                picker.FileTypeFilter.Add(".exe");
                picker.FileTypeFilter.Add(".dll");
                //picker.FileTypeFilter.Add(".winmd");

                var file = await picker.PickSingleFileAsync();
                ProgRing.IsActive = true;
                ProgRing.Visibility = Visibility.Visible;
                ProgRing.IsEnabled = true;
                LoadingText.Text = "Initilizing";
                /* if (file != null)
                 {
                     await file.CopyAsync(ApplicationData.Current.LocalFolder);
                 }     */

                // Application now has read/write access to the picked file
                PEInfoHeaderBox.Text = "Loaded: " + file.Path;
                PEFilename = file.Name;
                string token = StorageApplicationPermissions.FutureAccessList.Add(file);

                var buffer = await FileIO.ReadBufferAsync(file);
                var peHeader1 = new PeNet.PeFile(buffer.ToArray());
                var stream = await file.OpenStreamForReadAsync();
                PEStrings.IsPELoaded = "Yes";
                //peHeader1.
                LoadingText.Text = "Fetching Icon";
                var thumbnail = await file.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem, 100);
                var fileico = new BitmapImage();
                fileico.SetSource(thumbnail);
                FileIcon.Source = fileico;
                PEFileSize.Text = "File Size: " + ToFileSize(peHeader1.FileSize);


                LoadingText.Text = "Reading Export Table";
                if (peHeader1.ExportedFunctions == null)
                {
                    PEStrings.PEExportedFunctions = "No Exports Found";
                    ExportFuncOutput.Text = PEStrings.PEExportedFunctions;
                }
                else
                {

                    foreach (var exp in peHeader1.ExportedFunctions)
                    {

                        PEStrings.PEExportedFunctions = $"{exp.Name}  >  {exp.Address}  >  {exp.Ordinal}" + "\n";
                        ExportFuncOutput.Text = PEStrings.PEExportedFunctions;
                    }

                }


                ///
                /// Load Import table
                ///
                var idescs = peHeader1.ImageImportDescriptors;
                var bdescs = peHeader1.ImageBoundImportDescriptor;
                var ddescs = peHeader1.ImageDelayImportDescriptor;
                LoadingText.Text = "Reading Import Table";

                if (peHeader1.ImportedFunctions == null)
                {
                    PEStrings.PEImportedFunctions = "No Imports Found.";
                    ImportFuncOutput.Text = PEStrings.PEImportedFunctions;
                }
                else
                {
                    foreach (var imp in peHeader1.ImportedFunctions)
                    {
                        PEStrings.PEImportedFunctions += ($"{imp.DLL}" + "  >  " + $"{imp.Name}" + "\n");
                        ImportFuncOutput.Text = PEStrings.PEImportedFunctions;
                    }
                }

                if (Mono.Reflection.Image.IsAssembly(stream) == true)
                {
                    PEIsNET.Text = ".NET: True";
                }
                else
                {
                    PEIsNET.Text = ".NET: False";
                }
                ///
                ///
                /// Debug Info

                PESomeBorder.Visibility = Visibility.Visible;
                PESome.Text = "DEBUG INFORMATION" + "\n\n";
                PESome.Text +=$"Address of Raw Data: {peHeader1.ImageDebugDirectory.AddressOfRawData}\n" +
                             $"Pointer to Raw Data: {peHeader1.ImageDebugDirectory.PointerToRawData}\n" +
                             $"Time-Date Stamp: {peHeader1.ImageDebugDirectory.TimeDateStamp}\n" +
                             $"Major Version: {peHeader1.ImageDebugDirectory.MajorVersion}\n" +
                             $"Minor Version: {peHeader1.ImageDebugDirectory.MinorVersion}\n" +
                             $"Size of Data: {peHeader1.ImageDebugDirectory.SizeOfData}\n" +
                             $"Type: {peHeader1.ImageDebugDirectory.Type}\n" +
                             $"Characteristics: {peHeader1.ImageDebugDirectory.Characteristics}\n" +
                             $"Pdb Age: {peHeader1.ImageDebugDirectory.PdbAge}\n" +
                             $"Pdb Path/Name: {peHeader1.ImageDebugDirectory.PdbPath}\n" +
                             $"Pdb Signature: {peHeader1.ImageDebugDirectory.PdbSignature}";
                pdbhash = peHeader1.ImageDebugDirectory.PdbSignature.ToString();
                //PESome.Text += pdbhash;
                pdbname = file.Name.Split(".")[0];
                pdbUri = $"{MicrosoftSymbolsUrl}/{pdbname}.pdb/{pdbhash}1/{pdbname}.pdb";
                pdbDownld.Visibility = Visibility.Visible;



                PEHeadBoarder.Visibility = Visibility.Visible;
                PEMetaBorder2.Visibility = Visibility.Visible;
                DOSBorder.Visibility = Visibility.Visible;
                PEDOSHeader.Text = peHeader1.ImageDosHeader.ToString();
                LoadingText.Text = "Checking Directories";
                PEValidBoarder.Visibility = Visibility.Visible;
                PEHasValid.Text = ".NET VERSIONING" + "\n\n";
                //PEHasValid.Text += peHeader1.ClrComTypeLibId;

                if (Mono.Reflection.Image.IsAssembly(stream) == true)
                {
                    //PEHasValid.Text += "Information not found         " + "\n\n\n\n\n";
                    PEHasValid.Text += "Major: " + peHeader1.MetaDataHdr.MajorVersion + "  "
                                       + "\n" + "Minor: " + peHeader1.MetaDataHdr.MinorVersion
                                       + "\n" + "Version: " + peHeader1.MetaDataHdr.Version
                                       + "\n" + "Signature: " + peHeader1.MetaDataHdr.Signature
                                       + "\n" + "Reserved: " + peHeader1.MetaDataHdr.Reserved + "\n";
                }
                else
                {
                    PEValidBoarder.Visibility = Visibility.Collapsed;
                    PEHasValid.Visibility = Visibility.Collapsed;
                }
                PEHeader.Visibility = Visibility.Visible;
                LoadingText.Text = "Loading Section Headers";
                PEHeader.Text = peHeader1.ImageSectionHeaders[0].ToString();
                HashBoarder.Visibility = Visibility.Visible;
                LoadingText.Text = "Finding Hashes";

                PEHashes.Text = "SIGNAURES AND HASHES:" + "\n\n";
                PEHashes.Text += "SHA1: " + peHeader1.SHA1
                                + "\n" + "SHA256: " + peHeader1.SHA256
                                + "\n" + "MD5: " + peHeader1.MD5;
                // + "\n" + "Signature Cert: " + "\n" + peHeader1.Authenticode.SigningCertificate.ToString();




                if (peHeader1.WinCertificate == null)
                {
                    PEHashes.Text += "\n\n" + "Certification not found";
                }
                else
                {
                    PEHashes.Text += "\n\n" + "Certification:" + "\n" + peHeader1.WinCertificate;
                }


                ///
                /// Check if running on W10M
                ///
                if (ApiInformation.IsApiContractPresent("Windows.Phone.PhoneContract", 1))
                {
                    // do code for mobile
                    CopyrightText.Visibility = Visibility.Collapsed;
                    CopyrightText.Text = "Not supported on Windows Mobile";
                }
                else
                {
                    CopyrightText.Visibility = Visibility.Visible;
                    FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(file.Path);
                    CopyrightText.Text = "COPYRIGHT INFORMATION:" + "\n\n";
                    CopyrightText.Text += versionInfo.CompanyName + "\n"
                                        + versionInfo.LegalCopyright + "\n"
                                        + versionInfo.ProductName + "\n"
                                        + versionInfo.FileVersion + "\n"
                                        + versionInfo.Comments;
                }
                    


                

            

                LoadingText.Text = "Checking Assembly Info";
                if (peHeader1.MetaDataStreamTablesHeader != null)
                {
                    PEMetaBorder2.Visibility = Visibility.Visible;
                    PEMetaText2.Text = string.Join("\n", peHeader1.MetaDataHdr);

                }
                else
                {
                    PEMetaBorder2.Visibility = Visibility.Collapsed;
                }
                /* else
                {
                    PEMetaBorder1.Visibility = Visibility.Visible;

                    //String filearray = string.Join("\n", );
                    //PEdotnet.Text = peHeader1.MetaDataStreamString.ToString();
                    //PEdotnet.Text = peHeader1.MetaDataStreamTablesHeader.ToString();
                    //PEdotnet.Text = ;
                    //PEMetaData1.Text = string.Join("\n", peHeader1.);

                }*/



                ///
                /// dotnet disassembly
                /// 
                /*var stream = await file.OpenStreamForReadAsync();
                LoadingText.Text = "Testing Assembly";
                if (Mono.Reflection.Image.IsAssembly(stream) == true)
                {
                    Windows.Storage.StorageFolder storageFolder = Windows.Storage.ApplicationData.Current.LocalFolder;
                    Windows.Storage.StorageFile sampleFile = await storageFolder.GetFileAsync(file.Name);
                    var objpath = sampleFile.GetParentAsync();
                    //var decompile = new CSharpDecompiler(sampleFile.Path, new DecompilerSettings());
                    //PEFile testfile = new PEFile(sampleFile.Path);


                }*/



                LoadingText.Visibility = Visibility.Collapsed;
                ProgRing.IsActive = false;
                ProgRing.Visibility = Visibility.Collapsed;
                ProgRing.IsEnabled = false;
            }catch (Exception ex)
            {
                LoadingText.Visibility = Visibility.Collapsed;
                ProgRing.IsActive = false;
                ProgRing.Visibility = Visibility.Collapsed;
                ProgRing.IsEnabled = false;
                Exceptions.ThrownExceptionError(ex);
            }

        }
    


        

        public static async Task<byte[]> GetBytesAsync(StorageFile file)
        {
            byte[] bytes = null;
            if (file == null) return null;
            using (var stream = await file.OpenReadAsync())
            {
                bytes = new byte[stream.Size];
                using (var reader = new DataReader(stream))
                {
                    await reader.LoadAsync((uint)stream.Size);
                    reader.ReadBytes(bytes);
                }
            }
            byte[] buff = bytes;
            return bytes;
        }
        public static string ToFileSize(double value)
        {
            string[] suffixes = { "bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };
            for (int i = 0; i < suffixes.Length; i++)
            {
                if (value <= (Math.Pow(1024, i + 1)))
                {
                    return ThreeNonZeroDigits(value / Math.Pow(1024, i)) + " " + suffixes[i];
                }
            }

            return ThreeNonZeroDigits(value / Math.Pow(1024, suffixes.Length - 1)) +
                " " + suffixes[suffixes.Length - 1];
        }
        public static string ThreeNonZeroDigits(double value)
        {
            if (value >= 100)
            {
                // No digits after the decimal.
                return value.ToString("0,0");
            }
            else if (value >= 10)
            {
                // One digit after the decimal.
                return value.ToString("0.0");
            }
            else
            {
                // Two digits after the decimal.
                return value.ToString("0.00");
            }
        }

        public async void pdbDownld_Click(object sender, RoutedEventArgs e)
        {
            var userAgent = "Microsoft-Symbol-Server/10.0.10036.206";
            UserAgent.SetDefaultUserAgent(userAgent);


            try
            {
                string pdbGUID = pdbhash.Replace("-", "");

                FolderPicker folderPicker = new FolderPicker();
                folderPicker.SuggestedStartLocation = PickerLocationId.Downloads;
                //folderPicker.ViewMode = PickerViewMode.List;
                folderPicker.FileTypeFilter.Add("*");
                StorageFolder folder = await folderPicker.PickSingleFolderAsync();
                if (folder == null)
                {

                    return;
                }


                Uri uri = new Uri($"https://msdl.microsoft.com/download/symbols/" + $"{pdbname}.pdb/{pdbGUID}1/{pdbname}.pdb");


                StorageFile downloadedpdb = await folder.CreateFileAsync($"{pdbname}.pdb", CreationCollisionOption.ReplaceExisting);

                Windows.Web.Http.HttpClient httpClient = new Windows.Web.Http.HttpClient();

                var image = await httpClient.GetAsync(uri);

                using (IInputStream inputStream = await image.Content.ReadAsInputStreamAsync())
                {
                    using (IOutputStream outputStream = await downloadedpdb.OpenAsync(FileAccessMode.ReadWrite))
                    {
                        await RandomAccessStream.CopyAndCloseAsync(inputStream, outputStream);
                    }
                }

            }
            catch (Exception ex)
            {
                Exceptions.ThrownExceptionError(ex);
            }
        }
    }
}