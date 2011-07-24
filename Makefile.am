#  radreplay - radius test program which replays tcpdumps
#  Copyright (C) 2011 Ben Brown, Plusnet plc
#  
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

bin_PROGRAMS = radreplay
radreplay_SOURCES = radreplay.c radreplay.h util.c packet.c net.c compare.c radius.c ignore.c config.c
radreplay_sharedir = $(datadir)/radreplay
dist_radreplay_share_DATA = dictionary
dist_man_MANS = radreplay.1

ACLOCAL_AMFLAGS = -I m4
