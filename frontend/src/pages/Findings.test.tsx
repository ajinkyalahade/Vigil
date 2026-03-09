import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { expect, test } from "vitest";
import Findings from "./Findings";

test("renders findings page", () => {
  render(
    <BrowserRouter>
      <Findings />
    </BrowserRouter>,
  );
  expect(screen.getByText("Findings")).toBeInTheDocument();
});
