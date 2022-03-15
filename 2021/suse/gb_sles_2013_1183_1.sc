if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1183.1" );
	script_cve_id( "CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063", "CVE-2013-2066" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 19:08:00 +0000 (Mon, 28 Nov 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1183-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1183-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131183-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11' package(s) announced via the SUSE-SU-2013:1183-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of xorg-x11 fixes several security vulnerabilities.

 * Bug 815451- X.Org Security Advisory: May 23, 2013
 * Bug 821664 - libX11
 * Bug 821671 - libXv
 * Bug 821670 - libXt
 * Bug 821669 - libXrender
 * Bug 821668 - libXp
 * Bug 821667 - libXfixes
 * Bug 821665 - libXext
 * Bug 821663 - libFS, libXcursor, libXi, libXinerama,
libXRes, libXtst, libXvMC, libXxf86dga, libXxf86vm, libdmx

Security Issue references:

 * CVE-2013-1981
>
 * CVE-2013-1982
>
 * CVE-2013-1983
>
 * CVE-2013-1984
>
 * CVE-2013-1985
>
 * CVE-2013-1987
>
 * CVE-2013-1988
>
 * CVE-2013-1989
>
 * CVE-2013-1990
>
 * CVE-2013-1991
>
 * CVE-2013-1992
>
 * CVE-2013-1995
>
 * CVE-2013-1996
>
 * CVE-2013-1997
>
 * CVE-2013-1998
>
 * CVE-2013-1999
>
 * CVE-2013-2000
>
 * CVE-2013-2001
>
 * CVE-2013-2002
>
 * CVE-2013-2003
>
 * CVE-2013-2004
>
 * CVE-2013-2005
>
 * CVE-2013-2062
>
 * CVE-2013-2063
>
 * CVE-2013-2066
>" );
	script_tag( name: "affected", value: "'xorg-x11' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11", rpm: "xorg-x11~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xnest", rpm: "xorg-x11-Xnest~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvfb", rpm: "xorg-x11-Xvfb~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-devel-32bit", rpm: "xorg-x11-devel-32bit~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-devel", rpm: "xorg-x11-devel~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-devel-64bit", rpm: "xorg-x11-devel-64bit~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-doc", rpm: "xorg-x11-doc~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-100dpi", rpm: "xorg-x11-fonts-100dpi~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-75dpi", rpm: "xorg-x11-fonts-75dpi~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-cyrillic", rpm: "xorg-x11-fonts-cyrillic~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-scalable", rpm: "xorg-x11-fonts-scalable~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-syriac", rpm: "xorg-x11-fonts-syriac~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-32bit", rpm: "xorg-x11-libs-32bit~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs", rpm: "xorg-x11-libs~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-64bit", rpm: "xorg-x11-libs-64bit~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-x86", rpm: "xorg-x11-libs-x86~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-man", rpm: "xorg-x11-man~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-sdk", rpm: "xorg-x11-sdk~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-glx", rpm: "xorg-x11-server-glx~6.9.0~50.84.4", rls: "SLES10.0SP4" ) )){
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

