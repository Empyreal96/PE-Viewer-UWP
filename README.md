# PE Viewer for UWP

## What is it?

As a way to learn some better C# I started a small tool that views various info on .exe and .dll files, information like:

- PE DOS Header Info
- Signing and Hash Info
- Debug Header Info
- .PDB Symbol Downloading (Official MS files Only)
- Imported and Exported Functions
- Image Header Information
- ARM, ARM64, x86, x64 and W10M compatible 



<img src="/main.png" alt="main" width=370 /><img src="/phone.png" alt="main" width=250 />



### TODO's

- Fix some exceptions likely to occur in W10M
- Improve Information output
- UI
- .pdb download progress


### NOTES

- Solution is set to Build 16299, but compatible with 15063 with AppxManifest Version changing, a W10M compatible package will be provided.
- Pivot UI is to ensure it's compatible with 15063
- This will be prerelease for the foreseeable future!
- Expect Exception errors, bugs, issues to occur... I am learning in very little free time!
- This will be Read Only when viewing files, NO modification features are planned
- **Feel free to lend a hand, give feedback or just some moral support!**





### Credits and Acknowledgments

This project uses several nuget packages (Other packages in the solution are planned for future use below is what's 'active' in the current build):

- PeNet

- PeNet.Asn1

- System.*

- Mono.Reflection

  
