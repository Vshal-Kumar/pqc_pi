#!/bin/bash

gnome-terminal -- bash -c "./server; exec bash"
gnome-terminal -- bash -c "./server_rx; exec bash"
gnome-terminal -- bash -c "./server_tx; exec bash"