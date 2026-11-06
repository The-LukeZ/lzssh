import { mount } from "svelte";
import Demo from "./demo/Demo.svelte";

const target = document.getElementById("demo-root");
if (target) {
  target.replaceChildren();
  mount(Demo, { target });
}
