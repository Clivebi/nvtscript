if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883178" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_cve_id( "CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600", "CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856", "CVE-2018-15857", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2021-04-21 14:10:46 +0000 (Wed, 21 Apr 2021)" );
	script_name( "CentOS: Security Advisory for xorg-x11-drv-ati (CESA-2019:2079)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2019:2079" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-February/035636.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-drv-ati'
  package(s) announced via the CESA-2019:2079 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "X.Org is an open-source implementation of the X Window System. It provides
the basic low-level functionality that full-fledged graphical user
interfaces are designed upon.

Security Fix(es):

  * libX11: Crash on invalid reply in XListExtensions in ListExt.c
(CVE-2018-14598)

  * libX11: Off-by-one error in XListExtensions in ListExt.c (CVE-2018-14599)

  * libX11: Out of Bounds write in XListExtensions in ListExt.c
(CVE-2018-14600)

  * libxkbcommon: Invalid free in ExprAppendMultiKeysymList resulting in a
crash (CVE-2018-15857)

  * libxkbcommon: Endless recursion in xkbcomp/expr.c resulting in a crash
(CVE-2018-15853)

  * libxkbcommon: NULL pointer dereference resulting in a crash
(CVE-2018-15854)

  * libxkbcommon: NULL pointer dereference when handling xkb_geometry
(CVE-2018-15855)

  * libxkbcommon: Infinite loop when reaching EOL unexpectedly resulting in a
crash (CVE-2018-15856)

  * libxkbcommon: NULL pointer dereference when parsing invalid atoms in
ExprResolveLhs resulting in a crash (CVE-2018-15859)

  * libxkbcommon: NULL pointer dereference in ExprResolveLhs resulting in a
crash (CVE-2018-15861)

  * libxkbcommon: NULL pointer dereference in LookupModMask resulting in a
crash (CVE-2018-15862)

  * libxkbcommon: NULL pointer dereference in ResolveStateAndPredicate
resulting in a crash (CVE-2018-15863)

  * libxkbcommon: NULL pointer dereference in resolve_keysym resulting in a
crash (CVE-2018-15864)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section." );
	script_tag( name: "affected", value: "'xorg-x11-drv-ati' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-drv-ati", rpm: "xorg-x11-drv-ati~19.0.1~3.el7_7", rls: "CentOS7" ) )){
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

