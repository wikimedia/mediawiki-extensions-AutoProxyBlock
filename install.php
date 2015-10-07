<?php
require_once( dirname(__FILE__) . '/../../maintenance/commandLine.inc' );

if ( method_exists( 'User', 'newSystemUser' ) ) {
	$user = User::newSystemUser( 'AutoProxyBlock', array( 'steal' => true ) );
} else {
	$user = User::newFromName( 'AutoProxyBlock' );

	if ( !$user->getId() ) {
		$user->addToDatabase();
		$user->saveSettings();
		$ssu = new SiteStatsUpdate( 0, 0, 0, 0, 1 );
		$ssu->doUpdate();
	} else {
		$user->setPassword( null );
		$user->setEmail( null );
		$user->saveSettings();
	}
}
