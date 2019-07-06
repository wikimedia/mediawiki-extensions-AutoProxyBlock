<?php
/**
* AutoProxyBlock. Allows to automatically block or tag edits performed
* by proxies.
*
* Copyright (C) 2011 Cryptocoryne
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
require_once __DIR__ . '/../../../maintenance/commandLine.inc';

if ( method_exists( 'User', 'newSystemUser' ) ) {
	$user = User::newSystemUser( 'AutoProxyBlock', [ 'steal' => true ] );
} else {
	$user = User::newFromName( 'AutoProxyBlock' );

	if ( !$user->getId() ) {
		$user->addToDatabase();
		$user->saveSettings();
		$ssu = SiteStatsUpdate::factory( [ 'users' => 1 ] );
		$ssu->doUpdate();
	} else {
		$user->setPassword( null );
		$user->setEmail( null );
		$user->saveSettings();
	}
}
