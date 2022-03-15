if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871277" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-10-22 06:00:50 +0200 (Wed, 22 Oct 2014)" );
	script_cve_id( "CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6425", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "RedHat Update for wireshark RHSA-2014:1677-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Wireshark is a network protocol analyzer. It is used to capture and browse
the traffic running on a computer network.

Multiple flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash or,
possibly, execute arbitrary code as the user running Wireshark.
(CVE-2014-6429, CVE-2014-6430, CVE-2014-6431, CVE-2014-6432)

Several denial of service flaws were found in Wireshark. Wireshark could
crash or stop responding if it read a malformed packet off a network, or
opened a malicious dump file. (CVE-2014-6421, CVE-2014-6422, CVE-2014-6423,
CVE-2014-6425, CVE-2014-6428)

All wireshark users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running instances
of Wireshark must be restarted for the update to take effect." );
	script_tag( name: "affected", value: "wireshark on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:1677-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-October/msg00040.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~1.0.15~7.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "wireshark-debuginfo", rpm: "wireshark-debuginfo~1.0.15~7.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "wireshark-gnome", rpm: "wireshark-gnome~1.0.15~7.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

