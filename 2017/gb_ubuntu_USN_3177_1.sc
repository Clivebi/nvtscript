if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843024" );
	script_version( "2021-09-16T09:57:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 09:57:04 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-24 10:19:27 +0100 (Tue, 24 Jan 2017)" );
	script_cve_id( "CVE-2016-0762", "CVE-2016-5018", "CVE-2016-5388", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735", "CVE-2016-8745", "CVE-2016-9774", "CVE-2016-9775" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 22:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for tomcat8 USN-3177-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat8'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Tomcat realm implementations incorrectly handled
passwords when a username didn't exist. A remote attacker could possibly
use this issue to enumerate usernames. This issue only applied to Ubuntu
12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-0762)

Alvaro Munoz and Alexander Mirosh discovered that Tomcat incorrectly
limited use of a certain utility method. A malicious application could
possibly use this to bypass Security Manager restrictions. This issue only
applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-5018)

It was discovered that Tomcat did not protect applications from untrusted
data in the HTTP_PROXY environment variable. A remote attacker could
possibly use this issue to redirect outbound traffic to an arbitrary proxy
server. This issue only applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-5388)

It was discovered that Tomcat incorrectly controlled reading system
properties. A malicious application could possibly use this to bypass
Security Manager restrictions. This issue only applied to Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6794)

It was discovered that Tomcat incorrectly controlled certain configuration
parameters. A malicious application could possibly use this to bypass
Security Manager restrictions. This issue only applied to Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6796)

It was discovered that Tomcat incorrectly limited access to global JNDI
resources. A malicious application could use this to access any global JNDI
resource without an explicit ResourceLink. This issue only applied to
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6797)

Regis Leroy discovered that Tomcat incorrectly filtered certain invalid
characters from the HTTP request line. A remote attacker could possibly
use this issue to inject data into HTTP responses. (CVE-2016-6816)

Pierre Ernst discovered that the Tomcat JmxRemoteLifecycleListener did not
implement a recommended fix. A remote attacker could possibly use this
issue to execute arbitrary code. (CVE-2016-8735)

It was discovered that Tomcat incorrectly handled error handling in the
send file code. A remote attacker could possibly use this issue to access
information from other requests. (CVE-2016-8745)

Paul Szabo discovered that the Tomcat package incorrectly handled upgrades
and removals. A local attacker could possibly use this issue to obtain
root privileges. (CVE-2016-9774, CVE-2016-9775)" );
	script_tag( name: "affected", value: "tomcat8 on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3177-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3177-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|12\\.04 LTS|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.52-1ubuntu0.8", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.52-1ubuntu0.8", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.0.37-1ubuntu0.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "tomcat8", ver: "8.0.37-1ubuntu0.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.35-1ubuntu3.9", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "tomcat6", ver: "6.0.35-1ubuntu3.9", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.0.32-1ubuntu1.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "tomcat8", ver: "8.0.32-1ubuntu1.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

