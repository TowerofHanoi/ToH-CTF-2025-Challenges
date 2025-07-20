# The Challenge

The challenge presents itself as a service that allows uploading 0-byte files and subsequently downloading them.
The flag is located in the root of the filesystem.

The application only has four endpoints:

* `/`: lists all uploaded files
* `/upload`: allows uploading 0B files, but only within the `uploads` folder
* `/uploads/uuid`: allows downloading the uploaded file
* `/rename/uuid`: allows renaming the file

A trivial initial vulnerability lies in the fact that a single `../` path traversal is allowed, which makes it possible to upload files to the main folder of the challenge. This potentially allows overwriting (with a 0B file) the database file itself (which would just break the challenge).

The only other writable file in that folder is the journaling file (created and removed whenever an explicit transaction is performed).

# SQLite WTF

When you start a transaction in SQLite, you expect the database to be able to fully roll it back on request. At some point, I wondered: how much RAM can SQLite use to handle such operations? The answer is just 10 MB.

If the data involved in the transaction exceeds this threshold (for example, when replacing a string larger than 10 MB), SQLite uses a temporary on-disk file (the journal file) to perform a rollback in case of error.

This is where a curious behavior comes into play: if the journal file is emptied during a transaction, you would expect SQLite to no longer be able to roll back. This is actually true unless the modification involves data fields of the same size as those already present in the database.

In these particular cases, for example, when you execute a query that replaces a string with another of equal length, SQLite still manages to complete the transaction. However, if the journal file is removed during the operation, the transaction can only be partially rolled back, without SQLite raising clear errors. This behavior can lead to inconsistent database states, without obvious failure signals.

In my application, when passing a path of about 50 MB to the database, I observed that the journal file remains on disk for about 0.4 seconds (this is because Python's `normpath` is slow with 50MB). This short interval represents the only useful window to potentially manipulate it.

If I go ahead and actually empty this file during the transaction and then the transaction is reverted, the result is that the string in the DB at the end will be partially the one from the beginning of the transaction and partially the one from the supposedly successful transaction.
The resulting string in the DB is something like `ABBBBBA`, where A is part of the original string and B is part of the new string as if the transaction had succeeded.

To summarize, the steps are:

* Upload a file
* Rename that file using a long 50MB path `samepath` that, once normalized, points to `flag.txt`
* Rename the file again using another 50MB path that is identical to the previous one but with some `../../../` in the middle, i.e., a string like: `samepath[0:25MB]+'../../../'+samepath[25MB+9B:]`
* Exploit the race condition by uploading a 0B file at the path `../database.db-journal` (the path of the journal file) concurrently with the step above
* Open the file that now points to `../../../flag.txt`
* Win

# Remote

The biggest challenge in exploiting this remotely lies in correctly synchronizing the two requests for it to work.
To send a large request with more precise timing, a **single packet attack** is used so that the race condition can be timed only on the final packet, reducing the variable to network jitter alone.