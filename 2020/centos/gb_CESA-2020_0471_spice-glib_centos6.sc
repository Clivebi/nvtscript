if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883180" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2018-10893" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2020-02-12 04:00:48 +0000 (Wed, 12 Feb 2020)" );
	script_name( "CentOS: Security Advisory for spice-glib (CESA-2020:0471)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:0471" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-February/035638.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-glib'
  package(s) announced via the CESA-2020:0471 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for Simple
Protocol for Independent Computing Environments (SPICE) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of this
widget to access virtual machines using the SPICE protocol.

Security Fix(es):

  * spice-client: Insufficient encoding checks for LZ can cause different
integer/buffer overflows (CVE-2018-10893)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'spice-glib' package(s) on CentOS 6." );
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
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "spice-glib", rpm: "spice-glib~0.26~8.el6_10.2", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-glib-devel", rpm: "spice-glib-devel~0.26~8.el6_10.2", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk", rpm: "spice-gtk~0.26~8.el6_10.2", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-devel", rpm: "spice-gtk-devel~0.26~8.el6_10.2", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-python", rpm: "spice-gtk-python~0.26~8.el6_10.2", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-tools", rpm: "spice-gtk-tools~0.26~8.el6_10.2", rls: "CentOS6" ) )){
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

