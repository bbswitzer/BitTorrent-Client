# Brandon and Isaac's BitTorrent Client

Run a BitTorrent specification v1 compatible client in native Python using your command line!

# Supported Features

- Communicate with tracker using HTTP (with support for compact format)
- Download files from other instances of this BitTorrent client
- Download files from official BitTorrent clients
- Single and multiple file mode
- Advanced features:
  - Communicate with tracker using UDP
  - Optimistic unchoking algorithm
  - Rarest-first piece downloading strategy
  - Endgame mode


# Design and Implementation Choices

- Implemented in Python for ease of maintainability, collaboration, and memory safety
- Used all native python libraries; no external packages (besides `bencoder.py`)
- Split application logic into isolated and testable components
  - `bencoder.py` to encode and decode using bencoding
  - `bitfield.py` an abstraction of the bitfield with an intuitive API
  - `filestate.py` to manage writing and reading file pieces
  - `peers.py` to manage remote peer connections
  - `tracker.py` to manage relationship with remote tracker
  - `torrentfile.py` to handle parsing the torrent file and reading key attributes

# Problems Encountered

## Logic for Writing to Multiple Files

**Problem:** Torrent files can either be single-file mode where a single file is downloaded or multiple-file mode where multiple files are downloaded. In multiple file
mode, the files are treated as one contiguous file, and pieces may straddle two or more
files at once. This poses a challenge for reading and writing to the files.

**Solution:** We created an algorithm for reading and writing to one or multiple files that is given the piece, offset within that piece, the number of bytes to read or write, and a list of file descriptors. The algorithm finds the file descriptor that corresponds to the start of the block to read or write. The algorithm reads or writes `x` amount of bytes to that file, where `x` is the minimum of the number of bytes left in that file and the number of bytes left to read or write. If the end of the file is reached and there are still bytes left to write, the algorithm moves to the next file descriptor. This repeats until all of the bytes have been read or written.

## Testing downloading pieces via our hosted peer network

**Problem**: Testing downloading files from publicly available torrent networks was easy since we could download, *legally,* a `.torrent` from the internet and use it develop the logic for handshaking, interest, requesting pieces, and the rest of the "socket reading" functionality. However, on the other hand, testing that our "socket writing" functionality was working was much more difficult.

**Solution:** We implemented our own simple tracker http server in Python. The tracker server is configurable via a json file. You enter the name of the torrent file, the seed file, port, and a list of the peer information that has the file downloaded into the json configuration file and the python script starts a tracker server compatible with the BitTorrent specification.

In addition, we also created a "seed client" which is a sub-class of the torrent client. This client does not attempt to connect to other peers to download but instead has a reference to the original file to send across the peer-network.

When using the tracker http server in combination with the seed client, we could test sending pieces between different instances of our BitTorrent client.

## Finding Legal Torrent Files

**Problem:** Most torrent networks exist to share illegal media in a (mostly) untraceable way over the internet. When you search "\<KEYWORD\> torrent" on Google, you struggle to find legal torrent files to use for testing.

**Solution**: Someone on Piazza posted the link for a torrent of the Debian operating system ISO file which was obtained legally. We used this torrent file extensively for testing.

# Known Bugs or Limitations

- HTTP Tracker Server is limited to the static peer information provided in the tracker file. This is by design as the tracker is meant to allow the peers to connect to each other in the simplest way possible, without overhead.

# Usage

## Downloading and Seeding Public Torrents

These steps walk you through downloading and seeding a file from a public torrent.

### 1. Add a .torrent File
Download a .torrent file of your choosing and move it to `./torrents`.

### 2. Start the Torrent Client

Run the following commands in your terminal to begin the torrent:

```bash
cd client
```

```bash
python3 main.py -t ../torrents/<TORRENT FILE> --outdir bld --loglevel INFO
```

## Downloading from and Seeding to This Client

These steps walk you through hosting and downloading a file between multiple instances of this BitTorrent client. It will create processes for

1. A seed client
2. A tracker
3. A downloading client

### 1. Create a .torrent file

The first step is to create your .torrent file. You can do this with a tool such as [Transmission](https://transmissionbt.com/). Make sure to include http://localhost:\<SEED_CLIENT_PORT\>/announce as the tracker URL.

### 2. Start a Seed Torrent Client

```bash
export SEED_CLIENT_PORT=<YOUR PORT>
export PEER_CLIENT_PORT=<OTHER PORT>
export TORRENT_FILE=<PATH TO TORRENT FILE>
export SEED_FILE=<PATH TO SEED FILE>
```

```bash
cd client
```

```bash
python3 main.py -t $TORRENT_FILE -s $SEED_FILE --port $SEED_CLIENT_PORT --outdir build --loglevel INFO
```

This will start a seed BitTorrent client on `SEED_CLIENT_PORT` ready to listen for connections.

For more information on the command line arguments

```bash
python3 main.py -h
```


### 3. Start the Tracker Server 

The next step if creating a tracking server which will direct peer clients to the seed client(s). To add more seed clients, just repeat the seed client section with a different port and add it to the configuration file.

First step is entering the tracker server directory. From the root of the project

```bash
cd tracker
```

Open `tracker.toml` and make sure the peer information is consistent with the seed client. If your `SEED_CLIENT_PORT` is `6886` then your `tracker.toml` may look like.

```toml
port = 6881
torrentFile = "../torrents/jimmy.jpeg.torrent"

[[peers]]
peerId = "peer1"
ip = "127.0.0.1"
port = 6866
```

You can also use `tracker.json`

```json
{
  "port": 6969,
  "torrentFile": "../torrents/jimmy.jpeg.torrent",
  "peers": [
    {
      "ip": "127.0.0.1",
      "peerId": "peer1",
      "port": 6881
    }
  ]
}
```

To start the server, run

```bash
python3 main.py tracker.json
```

The sole argument is the path to the configuration file, either a `json` or `toml` file.

This will start the HTTP tracker server on the port specified in the configuration file via the `port` key.

### 4. Start the Torrent Client

From the root directory

```bash
cd client
```

```bash
python3 main.py -t ../torrents/jimmy.jpeg.torrent --port $PEER_CLIENT_PORT --outdir out --loglevel DEBUG
```

After running this command, the client should first communicate with the tracker server to get peer information and then begin requesting information from the seed client.
