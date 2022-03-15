if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876668" );
	script_version( "2021-09-02T08:01:23+0000" );
	script_cve_id( "CVE-2019-10143" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-02 08:01:23 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 14:22:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-08-14 02:34:40 +0000 (Wed, 14 Aug 2019)" );
	script_name( "Fedora Update for freeradius FEDORA-2019-9454ce61b2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-9454ce61b2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A6VKBZAZKJP5QKXDXRKCM2ZPZND3TFAX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeradius'
  package(s) announced via the FEDORA-2019-9454ce61b2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The FreeRADIUS Server Project is a high performance and highly configurable
GPL&#39, d free RADIUS server. The server is similar in some respects to
Livingston&#39, s 2.0 server.  While FreeRADIUS started as a variant of the
Cistron RADIUS server, they don&#39, t share a lot in common any more. It now has
many more features than Cistron or Livingston, and is much more configurable.

FreeRADIUS is an Internet authentication daemon, which implements the RADIUS
protocol, as defined in RFC 2865 (and others). It allows Network Access
Servers (NAS boxes) to perform authentication for dial-up users. There are
also RADIUS clients available for Web servers, firewalls, Unix logins, and
more.  Using RADIUS allows authentication and authorization for a network to
be centralized, and minimizes the amount of re-configuration which has to be
done when adding or deleting new users." );
	script_tag( name: "affected", value: "'freeradius' package(s) on Fedora 29." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "freeradius", rpm: "freeradius~3.0.19~3.fc29", rls: "FC29" ) )){
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

