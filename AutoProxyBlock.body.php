<?php

class AutoProxyBlock {
	static function isProxy( $ip ) {
		global $wgMemc, $wgAutoProxyBlockSources;

		$memcKey = wfMemcKey( 'isproxy', $ip );
		$data = $wgMemc->get( $memcKey );

		if( $data != '' ) {
			return ( $data === 'proxy' ) ? true : false;
		} else {
			if( isset($wgAutoProxyBlockSources['api']) ) {
				foreach($wgAutoProxyBlockSources['api'] as $url) {
					$request_options = array(
						'action' => 'query',
						'list' => 'blocks',
						'bkip' => $ip,
						'bklimit' => '1',
						'bkprop' => 'expiry|reason',
					);
					$ban = self::requestForeignAPI($url, $request_options);
					if( isset($ban['query']['blocks'][0]) && preg_match($wgAutoProxyBlockSources['key'], $ban['query']['blocks'][0]['reason']) ) {
						$wgMemc->set( $memcKey, 'proxy', 60 * 60 * 24 );
						return true;
					}
				}
			}

			if( isset($wgAutoProxyBlockSources['raw']) ) {
				$list = array();
				foreach($wgAutoProxyBlockSources['raw'] as $file) {
					if( file_exists($file) ) {
						$p = file($file);
						if( $p ) {
							array_merge($list, $p);
						}
					}
				}

				if ( in_array( $ip, array_unique($list) ) ) {
					$wgMemc->set( $memcKey, 'proxy', 60 * 60 * 24 );
					return true;
				} else {
					$wgMemc->set( $memcKey, 'not', 60 * 60 * 24 );
					return false;
				}
			}

			return false;
		}
	}

	static function checkProxy( $title, $user, $action, &$result ) {
		global $wgProxyCanPerform, $wgAutoProxyBlockLog, $wgRequest;

		if( in_array( $action, $wgProxyCanPerform ) || $user->isAllowed('proxyunbannable') ) {
			return true;
		}

		$userIP = $wgRequest->getIP();
		if( self::isProxy( $userIP ) ) {
			if( $wgAutoProxyBlockLog ) {
				$log = new LogPage( 'proxyblock' );
				$log->addEntry( 'blocked', $title, false, array( $action, $user->getName() ) );

				// hack for 1.19-
				$dbw = wfGetDB( DB_MASTER );
				$blocker = User::newFromName( 'AutoProxyBlock' );
				$dbw->update(
					'logging',
					array( 'log_user' => $blocker->getID(), 'log_user_text' => 'AutoProxyBlock' ),
					array( 'log_type' => 'proxyblock', 'log_user_text' => $user->getName() ),
					__METHOD__,
					array( 'ORDER BY' => 'log_timestamp DESC' )
				);
			}
			$result[] = array( 'proxy-blocked', $userIP );
			return false;
		}

		return true;
	}

	function AFSetVar( &$vars, $title ) {
		global $wgRequest;
		$vars->setVar( 'is_proxy', self::isProxy( $wgRequest->getIP() ) ? 1 : 0 );
		return true;
	}

	function AFBuilderVars( &$builder ) {
		$builder['vars']['is_proxy'] = 'is-proxy';
		return true;
	}
 
	function tagProxyChange( $recentChange ) {
		global $wgTagProxyActions, $wgUser, $wgRequest;

		if ( $wgTagProxyActions && self::isProxy( $wgRequest->getIP() ) && !$wgUser->isAllowed( 'notagproxychanges' ) ) {
			ChangeTags::addTags( 
				'proxy',
				$recentChange->mAttribs['rc_id'],
				$recentChange->mAttribs['rc_this_oldid'],
				$recentChange->mAttribs['rc_logid'] 
			);
		}
		return true;
	}

	static function addProxyTag( &$emptyTags ) {
		global $wgTagProxyActions;

		if ( $wgTagProxyActions ) {
			$emptyTags[] = 'proxy';
		}
		return true;
	}

	static function requestForeignAPI( $url, $options ) {
		$url .= '?format=json&' . wfArrayToCgi( $options );

		$content = Http::get( $url );
		return json_decode( $content, true );
	}
}
