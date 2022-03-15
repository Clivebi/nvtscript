if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882007" );
	script_version( "2020-02-18T15:18:54+0000" );
	script_tag( name: "last_modification", value: "2020-02-18 15:18:54 +0000 (Tue, 18 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-09-10 06:20:14 +0200 (Wed, 10 Sep 2014)" );
	script_cve_id( "CVE-2014-4607" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for lzo CESA-2014:0861 centos7" );
	script_tag( name: "insight", value: "LZO is a portable lossless data compression library written in ANSI C.

An integer overflow flaw was found in the way the lzo library decompressed
certain archives compressed with the LZO algorithm. An attacker could
create a specially crafted LZO-compressed input that, when decompressed by
an application using the lzo library, would cause that application to crash
or, potentially, execute arbitrary code. (CVE-2014-4607)

Red Hat would like to thank Don A. Bailey from Lab Mouse Security for
reporting this issue.

All lzo users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to take
effect, all services linked to the lzo library must be restarted or the
system rebooted." );
	script_tag( name: "affected", value: "lzo on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0861" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-July/020406.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lzo'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "lzo", rpm: "lzo~2.06~6.el7_0.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lzo-devel", rpm: "lzo-devel~2.06~6.el7_0.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lzo-minilzo", rpm: "lzo-minilzo~2.06~6.el7_0.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

