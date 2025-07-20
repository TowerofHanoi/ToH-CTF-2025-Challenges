The challenge presents itself as a service that allows uploading 0-byte files and subsequently downloading them.
The flag is located in the root of the filesystem.

The application only has four endpoints:

* `/`: lists all uploaded files
* `/upload`: allows uploading 0B files, but only within the `uploads` folder
* `/uploads/uuid`: allows downloading the uploaded file
* `/rename/uuid`: allows renaming the file

The vulnerability is trivial and involves exploiting a race condition between rename and the file get.