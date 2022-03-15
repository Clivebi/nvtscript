if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844632" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2016-0762", "CVE-2016-5018", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 22:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-01 03:00:39 +0000 (Thu, 01 Oct 2020)" );
	script_name( "Ubuntu: Security Advisory for tomcat6 (USN-4557-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4557-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005668.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat6'
  package(s) announced via the USN-4557-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Tomcat realm implementations incorrectly handled
passwords when a username didn't exist. A remote attacker could possibly
use this issue to enumerate usernames. (CVE-2016-0762)

Alvaro Munoz and Alexander Mirosh discovered that Tomcat incorrectly
limited use of a certain utility method. A malicious application could
possibly use this to bypass Security Manager restrictions. (CVE-2016-5018)

It was discovered that Tomcat incorrectly controlled reading system
properties. A malicious application could possibly use this to bypass
Security Manager restrictions. (CVE-2016-6794)

It was discovered that Tomcat incorrectly controlled certain configuration
parameters. A malicious application could possibly use this to bypass
Security Manager restrictions. (CVE-2016-6796)

It was discovered that Tomcat incorrectly limited access to global JNDI
resources. A malicious application could use this to access any global JNDI
resource without an explicit ResourceLink. (CVE-2016-6797)

Regis Leroy discovered that Tomcat incorrectly filtered certain invalid
characters from the HTTP request line. A remote attacker could possibly
use this issue to inject data into HTTP responses. (CVE-2016-6816)

Pierre Ernst discovered that the Tomcat JmxRemoteLifecycleListener did not
implement a recommended fix. A remote attacker could possibly use this
issue to execute arbitrary code. (CVE-2016-8735)" );
	script_tag( name: "affected", value: "'tomcat6' package(s) on Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libservlet2.5-java", ver: "6.0.45+dfsg-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

