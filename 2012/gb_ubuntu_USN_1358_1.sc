if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1358-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840891" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-13 16:32:26 +0530 (Mon, 13 Feb 2012)" );
	script_cve_id( "CVE-2011-4885", "CVE-2012-0830", "CVE-2011-4153", "CVE-2012-0057", "CVE-2012-0788", "CVE-2012-0831", "CVE-2011-0441" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1358-1" );
	script_name( "Ubuntu Update for php5 USN-1358-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1358-1" );
	script_tag( name: "affected", value: "php5 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that PHP computed hash values for form parameters
  without restricting the ability to trigger hash collisions predictably.
  This could allow a remote attacker to cause a denial of service by
  sending many crafted parameters. (CVE-2011-4885)

  ATTENTION: this update changes previous PHP behavior by
  limiting the number of external input variables to 1000.
  This may be increased by adding a 'max_input_vars'
  directive to the php.ini configuration file. See
  the references for more information.

  Stefan Esser discovered that the fix to address the predictable hash
  collision issue, CVE-2011-4885, did not properly handle the situation
  where the limit was reached. This could allow a remote attacker to
  cause a denial of service or execute arbitrary code via a request
  containing a large number of variables. (CVE-2012-0830)

  It was discovered that PHP did not always check the return value of
  the zend_strndup function. This could allow a remote attacker to
  cause a denial of service. (CVE-2011-4153)

  It was discovered that PHP did not properly enforce libxslt security
  settings. This could allow a remote attacker to create arbitrary
  files via a crafted XSLT stylesheet that uses the libxslt output
  extension. (CVE-2012-0057)

  It was discovered that PHP did not properly enforce that PDORow
  objects could not be serialized and not be saved in a session. A
  remote attacker could use this to cause a denial of service via an
  application crash. (CVE-2012-0788)

  It was discovered that PHP allowed the magic_quotes_gpc setting to
  be disabled remotely. This could allow a remote attacker to bypass
  restrictions that could prevent an SQL injection. (CVE-2012-0831)

  USN 1126-1 addressed an issue where the /etc/cron.d/php5 cron job
  for PHP allowed local users to delete arbitrary files via a symlink
  attack on a directory under /var/lib/php5/. Emese Revfy discovered
  that the fix had not been applied to PHP for Ubuntu 10.04 LTS. This
  update corrects the issue. We apologize for the error. (CVE-2011-0441)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.php.net/manual/en/info.configuration.php#ini.max-input-vars" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.3-1ubuntu9.9", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5", ver: "5.3.3-1ubuntu9.9", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.3-1ubuntu9.9", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.3-1ubuntu9.9", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.3.3-1ubuntu9.9", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.3.3-1ubuntu9.9", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.2-1ubuntu4.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5", ver: "5.3.2-1ubuntu4.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.2-1ubuntu4.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.2-1ubuntu4.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.3.2-1ubuntu4.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.3.2-1ubuntu4.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.5-1ubuntu7.6", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5", ver: "5.3.5-1ubuntu7.6", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.5-1ubuntu7.6", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.5-1ubuntu7.6", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.3.5-1ubuntu7.6", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.3.5-1ubuntu7.6", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.2.4-2ubuntu5.22", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5", ver: "5.2.4-2ubuntu5.22", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.2.4-2ubuntu5.22", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.2.4-2ubuntu5.22", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.2.4-2ubuntu5.22", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.2.4-2ubuntu5.22", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

