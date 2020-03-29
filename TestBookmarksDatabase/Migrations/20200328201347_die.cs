using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace TestBookmarksDatabase.Migrations
{
    public partial class die : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: new Guid("11111111-1111-1111-1111-111111111111"),
                column: "ConcurrencyStamp",
                value: "126a20ca-9c16-4954-8b56-e7ed247fa6ef");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { new Guid("77777777-7777-7777-7777-777777777777"), "3153e579-af95-4ea4-8f5f-59a51a621eed", "User", null });

            migrationBuilder.UpdateData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: new Guid("11111111-1111-1111-1111-111111111111"),
                columns: new[] { "ConcurrencyStamp", "PasswordHash" },
                values: new object[] { "0d6ef654-19a6-48f6-b801-7fbc3f90fefb", "AQAAAAEAACcQAAAAEIDJKEV3jAxmQtasgnyamd+AwnkFv5vCFrvM71X+mEyeei2z1zX5RPuXA+L32iQfPQ==" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: new Guid("77777777-7777-7777-7777-777777777777"));

            migrationBuilder.UpdateData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: new Guid("11111111-1111-1111-1111-111111111111"),
                column: "ConcurrencyStamp",
                value: "423af13a-c957-4a49-8945-919140f075b6");

            migrationBuilder.UpdateData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: new Guid("11111111-1111-1111-1111-111111111111"),
                columns: new[] { "ConcurrencyStamp", "PasswordHash" },
                values: new object[] { "60515109-1afd-4b2f-8c6e-8051940f6322", "AQAAAAEAACcQAAAAELYWm8337legqdZKkTmRmOJLJ2CHA0Oyn4tyASPMhj9vezN5Hx3cc7cQuWgqtkse1w==" });
        }
    }
}
