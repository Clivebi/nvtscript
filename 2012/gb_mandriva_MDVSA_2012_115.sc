if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:115" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831703" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-30 11:22:50 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-3570", "CVE-2012-3571", "CVE-2012-3954" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "MDVSA", value: "2012:115" );
	script_name( "Mandriva Update for dhcp MDVSA-2012:115 (dhcp)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhcp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2011\\.0" );
	script_tag( name: "affected", value: "dhcp on Mandriva Linux 2011.0" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Multiple vulnerabilities has been discovered and corrected in ISC DHCP:

  An unexpected client identifier parameter can cause the ISC DHCP
  daemon to segmentation fault when running in DHCPv6 mode, resulting
  in a denial of service to further client requests. In order to exploit
  this condition, an attacker must be able to send requests to the DHCP
  server (CVE-2012-3570)

  Two memory leaks have been found and fixed in ISC DHCP. Both are
  reproducible when running in DHCPv6 mode (with the -6 command-line
  argument.) The first leak is confirmed to only affect servers
  operating in DHCPv6 mode, but based on initial code analysis the
  second may theoretically affect DHCPv4 servers (though this has not
  been demonstrated.) (CVE-2012-3954).

  The updated packages have been upgraded to the latest version
  (4.2.4-P1) which is not affected by these issues." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2011.0"){
	if(( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~4.2.4~0.P1.1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.2.4~0.P1.1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.2.4~0.P1.1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-doc", rpm: "dhcp-doc~4.2.4~0.P1.1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~4.2.4~0.P1.1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~4.2.4~0.P1.1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

